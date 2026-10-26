import { serve } from "@hono/node-server";
import dotenvFlow from "dotenv-flow";
import { Hono, type Context } from "hono";
import { getSignedCookie, setSignedCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import { logger } from "hono/logger";
import * as client from "openid-client";
import * as z from "zod";
import { ErrorPage } from "./views/error.tsx";
import { IndexPage } from "./views/index.tsx";
import { NotFoundPage } from "./views/not_found.tsx";

dotenvFlow.config({
  default_node_env: "development",
});

const optional_string = z
  .string()
  .optional()
  .transform((value) => (value === "" ? undefined : value));
const optional_list = optional_string.transform((value) => value?.split(","));
const flag = z.stringbool().default(false);

const env = z
  .object({
    ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT: optional_string,
    ACR_VALUES: optional_list,
    ACR_VALUES_FOR_MFA: optional_list,
    CALLBACK_URL: z.string().startsWith("/"),
    CLIENT_ID: z.string().min(1),
    CLIENT_SECRET: z.string().min(1),
    EXTRA_PARAM_SP_NAME: optional_string,
    HOST: z.url(),
    ID_TOKEN_SIGNED_RESPONSE_ALG: optional_string,
    IS_HTTP_PROTOCOL_FORBIDDEN: flag,
    LOGIN_HINT: optional_string,
    PORT: z.coerce.number().int().default(3000),
    PROVIDER: z.url(),
    SCOPES: z.string().min(1),
    SESSION_SECRET: z.string().min(1),
    SHOW_BETA_FEATURES: flag,
    SITE_TITLE: z.string(),
    STYLESHEET_URL: optional_string,
    USERINFO_SIGNED_RESPONSE_ALG: optional_string,
  })
  .parse(process.env);

const CustomConnectionBody = z.object({
  "custom-params": z
    .string()
    .transform((value): unknown => JSON.parse(value))
    .pipe(z.record(z.string(), z.unknown())),
});

type SignedIn = {
  id_token_hint: string | undefined;
  idtoken: client.IDToken;
  oauth2token: client.TokenEndpointResponse;
  userinfo: client.UserInfoResponse;
};
type Session = {
  pending_login?: { nonce: string; state: string };
  signed_in?: SignedIn;
};
type AppEnv = { Variables: { session: Session; session_id: string } };

const sessions = new Map<string, Session>();

const session = createMiddleware<AppEnv>(async (c, next) => {
  const signed_session_id = await getSignedCookie(
    c,
    env.SESSION_SECRET,
    "pc_session",
  );
  const session_id =
    typeof signed_session_id === "string"
      ? signed_session_id
      : crypto.randomUUID();
  const current = sessions.get(session_id) ?? {};
  sessions.set(session_id, current);
  c.set("session", current);
  c.set("session_id", session_id);
  await setSignedCookie(c, "pc_session", session_id, env.SESSION_SECRET, {
    httpOnly: true,
    path: "/",
  });
  await next();
});

const app = new Hono().use(logger()).use(session);

const obj_to_url_params = (obj: Record<string, unknown>) =>
  new URLSearchParams(
    Object.entries(obj)
      .filter(([, value]) => Boolean(value))
      .map(([key, value]): [string, string] => [
        key,
        typeof value === "string" ? value : JSON.stringify(value),
      ]),
  );

const config_options = env.IS_HTTP_PROTOCOL_FORBIDDEN
  ? undefined
  : { execute: [client.allowInsecureRequests] };

const get_provider_config = () =>
  client.discovery(
    new URL(env.PROVIDER),
    env.CLIENT_ID,
    {
      ...(env.ID_TOKEN_SIGNED_RESPONSE_ALG !== undefined && {
        id_token_signed_response_alg: env.ID_TOKEN_SIGNED_RESPONSE_ALG,
      }),
      ...(env.USERINFO_SIGNED_RESPONSE_ALG !== undefined && {
        userinfo_signed_response_alg: env.USERINFO_SIGNED_RESPONSE_ALG,
      }),
    },
    client.ClientSecretPost(env.CLIENT_SECRET),
    config_options,
  );

const AUTHORIZATION_DEFAULT_PARAMS = {
  redirect_uri: `${env.HOST}${env.CALLBACK_URL}`,
  scope: env.SCOPES,
  login_hint: env.LOGIN_HINT ?? null,
  acr_values: env.ACR_VALUES ?? null,
  claims: {
    id_token: {
      amr: {
        essential: true,
      },
    },
  },
};

app.get("/", (c) => {
  const { signed_in } = c.var.session;
  return c.html(
    IndexPage({
      view: {
        default_params_value: JSON.stringify(
          AUTHORIZATION_DEFAULT_PARAMS,
          null,
          2,
        ),
        session: signed_in
          ? {
              kind: "signed_in",
              idtoken: JSON.stringify(signed_in.idtoken, null, 2),
              oauth2token: JSON.stringify(signed_in.oauth2token, null, 2),
              userinfo: JSON.stringify(signed_in.userinfo, null, 2),
            }
          : { kind: "anonymous" },
        show_beta_features: env.SHOW_BETA_FEATURES,
        stylesheet_url: env.STYLESHEET_URL,
        title: env.SITE_TITLE,
      },
    }),
  );
});

const get_authorization_controller_factory = (
  params: object = {},
  options?: { should_replace_default_params: boolean },
) => {
  const should_replace_default_params =
    options?.should_replace_default_params === true;
  return async (c: Context<AppEnv>) => {
    const config = await get_provider_config();
    const nonce = client.randomNonce();
    const state = client.randomState();

    c.var.session.pending_login = { nonce, state };

    const computed_params = should_replace_default_params
      ? params
      : { ...AUTHORIZATION_DEFAULT_PARAMS, ...params };

    const redirect_url = client.buildAuthorizationUrl(
      config,
      obj_to_url_params({
        nonce,
        state,
        ...computed_params,
        ...(env.EXTRA_PARAM_SP_NAME !== undefined && {
          sp_name: env.EXTRA_PARAM_SP_NAME,
        }),
      }),
    );
    return c.redirect(redirect_url.href);
  };
};

app.post("/login", get_authorization_controller_factory());

app.post(
  "/login-full-acr",
  get_authorization_controller_factory({
    claims: {
      id_token: {
        amr: { essential: true },
        acr: {
          essential: true,
          values: [
            "eidas0",
            "eidas0-mfa",
            "eidas1",
            "eidas1-mfa",
            "eidas2",
            "eidas3",
          ],
        },
      },
    },
  }),
);

app.post(
  "/select-organization",
  get_authorization_controller_factory({
    prompt: "select_organization",
  }),
);

app.post(
  "/update-userinfo",
  get_authorization_controller_factory({
    prompt: "update_userinfo",
  }),
);

app.post(
  "/force-login",
  get_authorization_controller_factory({
    claims: {
      id_token: {
        amr: { essential: true },
        auth_time: { essential: true },
      },
    },
    prompt: "login",
    // alternatively, you can use the 'max_age: 0'
    // if so, claims parameter is not necessary as auth_time will be returned
  }),
);

app.post(
  "/force-2fa",
  get_authorization_controller_factory({
    claims: {
      id_token: {
        amr: { essential: true },
        acr: {
          essential: true,
          values: env.ACR_VALUES_FOR_MFA ?? null,
        },
      },
    },
  }),
);

app.post(
  "/force-certification-dirigeant",
  get_authorization_controller_factory({
    claims: {
      id_token: {
        acr: {
          essential: true,
          value: env.ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT,
        },
      },
    },
  }),
);

app.post("/custom-connection", async (c) => {
  const body = CustomConnectionBody.parse(await c.req.parseBody());

  return get_authorization_controller_factory(body["custom-params"], {
    should_replace_default_params: true,
  })(c);
});

app.get(env.CALLBACK_URL, async (c) => {
  const { session } = c.var;
  const current_url = new URL(c.req.url);
  const forwarded_proto = c.req
    .header("x-forwarded-proto")
    ?.split(",")[0]
    ?.trim();
  if (forwarded_proto !== undefined && forwarded_proto !== "")
    current_url.protocol = forwarded_proto;

  const error = c.req.query("error");
  if (error !== undefined && error !== "") {
    throw new client.AuthorizationResponseError(
      `${error} - ${c.req.query("error_description")}`,
      { cause: current_url.searchParams },
    );
  }

  const config = await get_provider_config();

  const { pending_login } = session;
  const tokens = await client.authorizationCodeGrant(
    config,
    current_url,
    pending_login === undefined
      ? undefined
      : {
          expectedNonce: pending_login.nonce,
          expectedState: pending_login.state,
        },
  );

  delete session.pending_login;
  const claims = tokens.claims();
  if (!claims) throw new Error("ID Token missing from the token response");
  session.signed_in = {
    id_token_hint: tokens.id_token,
    idtoken: claims,
    oauth2token: tokens,
    userinfo: await client.fetchUserInfo(
      config,
      tokens.access_token,
      claims.sub,
    ),
  };
  return c.redirect("/");
});

app.post("/logout", async (c) => {
  const id_token_hint = c.var.session.signed_in?.id_token_hint;
  sessions.delete(c.var.session_id);
  const config = await get_provider_config();
  const redirect_url = client.buildEndSessionUrl(
    config,
    obj_to_url_params({
      post_logout_redirect_uri: `${env.HOST}/`,
      id_token_hint,
    }),
  );

  return c.redirect(redirect_url.href);
});

app.onError((err, c) => {
  console.error(err);

  return c.html(
    ErrorPage({
      error: err.name,
      error_description: err.message,
      stylesheet_url: env.STYLESHEET_URL,
      title: `Error - ${env.SITE_TITLE}`,
    }),
    500,
  );
});

app.notFound((c) =>
  c.html(
    NotFoundPage({
      path: c.req.path,
      stylesheet_url: env.STYLESHEET_URL,
      title: `Not found - ${env.SITE_TITLE}`,
    }),
    404,
  ),
);

serve({ fetch: app.fetch, port: env.PORT }, ({ port }) => {
  console.log(`App listening on port ${port}`);
});
