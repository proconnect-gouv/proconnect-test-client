import dotenv_flow from "dotenv-flow";
import express from "express";
import expressLayouts from "express-ejs-layouts";
import * as client from "openid-client";
import session from "express-session";
import morgan from "morgan";
import { chain, isObject } from "lodash-es";
import path from "path";
import { fileURLToPath } from "url";
import { z } from "zod/v4";

//

dotenv_flow.config({
  default_node_env: "development",
});

const {
  ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT_2FA,
  ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT,
  ACR_VALUE_FOR_CONSISTENCY_CHECKED_2FA,
  ACR_VALUE_FOR_EIDAS2,
  ACR_VALUE_FOR_EIDAS3,
  ACR_VALUE_FOR_SELF_ASSERTED_2FA,
  ACR_VALUES,
  CALLBACK_URL,
  EXTRA_PARAM_SP_NAME,
  HOST,
  IS_HTTP_PROTOCOL_FORBIDDEN,
  LOGIN_HINT,
  NODE_ENV,
  PC_CLIENT_ID,
  PC_CLIENT_SECRET,
  PC_ID_TOKEN_SIGNED_RESPONSE_ALG,
  PC_PROVIDER,
  PC_SCOPES,
  PC_USERINFO_SIGNED_RESPONSE_ALG,
  PORT,
  SESSION_SECRET,
  SITE_TITLE,
} = z
  .object({
    ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT_2FA: z.string(),
    ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT: z.string(),
    ACR_VALUE_FOR_CONSISTENCY_CHECKED_2FA: z.string(),
    ACR_VALUE_FOR_EIDAS2: z.string(),
    ACR_VALUE_FOR_EIDAS3: z.string(),
    ACR_VALUE_FOR_SELF_ASSERTED_2FA: z.string(),
    ACR_VALUES: z
      .string()
      .transform((v) => v.split(","))
      .default(null),
    CALLBACK_URL: z.string(),
    EXTRA_PARAM_SP_NAME: z.string(),
    SITE_TITLE: z.string(),
    HOST: z.string(),
    IS_HTTP_PROTOCOL_FORBIDDEN: z.enum(["True", "False"]).default("True"),
    LOGIN_HINT: z.string(),
    NODE_ENV: z.enum(["development", "production"]).default("development"),
    PC_CLIENT_ID: z.string().min(1),
    PC_CLIENT_SECRET: z.string().min(1),
    PC_ID_TOKEN_SIGNED_RESPONSE_ALG: z.string().optional(),
    PC_PROVIDER: z.url(),
    PC_SCOPES: z.string(),
    PC_USERINFO_SIGNED_RESPONSE_ALG: z.string().optional(),
    PORT: z.coerce.number().int().min(80).max(65535).default(3000),
    SESSION_SECRET: z.string().min(1).max(100),
  })
  .parse(process.env);

console.table({
  ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT,
  ACR_VALUE_FOR_CONSISTENCY_CHECKED_2FA,
  ACR_VALUE_FOR_EIDAS2,
  ACR_VALUE_FOR_EIDAS3,
  ACR_VALUES,
  CALLBACK_URL,
  EXTRA_PARAM_SP_NAME,
  HOST,
  NODE_ENV,
  PC_CLIENT_ID,
  PC_ID_TOKEN_SIGNED_RESPONSE_ALG,
  PC_PROVIDER,
  PC_SCOPES,
  PC_USERINFO_SIGNED_RESPONSE_ALG,
  PORT,
  SITE_TITLE,
});
//

const app = express();

app.set("view engine", "ejs");
app.set("trust proxy", 1);

app.use(
  session({
    name: "pc_session",
    resave: false,
    saveUninitialized: true,
    secret: SESSION_SECRET,
    cookie: {
      secure: NODE_ENV === "production",
      sameSite: "lax",
    },
  }),
);
app.use(expressLayouts);
app.set("layout", "pages/main");
app.use(morgan("combined"));

app.use(express.static("public"));

const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(
  "/dsfr",
  express.static(path.join(__dirname, "node_modules/@gouvfr/dsfr/dist")),
);

const objToUrlParams = (obj) =>
  new URLSearchParams(
    chain(obj)
      .omitBy((v) => !v)
      .mapValues((o) => (isObject(o) ? JSON.stringify(o) : o))
      .value(),
  );

const getCurrentUrl = (req) =>
  new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);

const configOptions =
  IS_HTTP_PROTOCOL_FORBIDDEN === "True"
    ? undefined
    : { execute: [client.allowInsecureRequests] };

const getProviderConfig = async () => {
  const config = await client.discovery(
    new URL(PC_PROVIDER),
    PC_CLIENT_ID,
    {
      id_token_signed_response_alg: PC_ID_TOKEN_SIGNED_RESPONSE_ALG,
      userinfo_signed_response_alg: PC_USERINFO_SIGNED_RESPONSE_ALG,
    },
    client.ClientSecretPost(PC_CLIENT_SECRET),
    configOptions,
  );
  return config;
};

const AUTHORIZATION_DEFAULT_PARAMS = {
  redirect_uri: `${HOST}${CALLBACK_URL}`,
  scope: PC_SCOPES,
  login_hint: LOGIN_HINT || null,
  claims: { id_token: { amr: { essential: true } } },
  sp_name: EXTRA_PARAM_SP_NAME,
};

app.get("/", async (req, res, next) => {
  try {
    res.render("pages/index", {
      title: SITE_TITLE,
      userinfo: req.session.userinfo,
      idtoken: req.session.idtoken,
    });
  } catch (e) {
    next(e);
  }
});

const getAuthorizationControllerFactory = (extraParams) => {
  return async (req, res, next) => {
    try {
      const config = await getProviderConfig();
      const nonce = client.randomNonce();
      const state = client.randomState();

      req.session.state = state;
      req.session.nonce = nonce;

      const redirectUrl = client.buildAuthorizationUrl(
        config,
        objToUrlParams({
          nonce,
          state,
          ...AUTHORIZATION_DEFAULT_PARAMS,
          ...extraParams,
        }),
      );

      res.redirect(redirectUrl);
    } catch (e) {
      next(e);
    }
  };
};

app.post(
  "/login",
  getAuthorizationControllerFactory({
    claims: {
      id_token: {
        acr: { essential: true },
        amr: { essential: true },
        auth_time: { essential: true },
      },
    },
  }),
);

app.post(
  "/force-2fa",
  getAuthorizationControllerFactory({
    claims: {
      id_token: {
        acr: {
          essential: true,
          values: [
            ACR_VALUE_FOR_EIDAS2,
            ACR_VALUE_FOR_EIDAS3,
            ACR_VALUE_FOR_SELF_ASSERTED_2FA,
            ACR_VALUE_FOR_CONSISTENCY_CHECKED_2FA,
          ],
        },
        amr: { essential: true },
      },
    },
  }),
);

app.post(
  "/force-certification-dirigeant",
  getAuthorizationControllerFactory({
    claims: {
      id_token: {
        acr: {
          essential: true,
          values: [
            ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT,
            ACR_VALUE_FOR_CERTIFICATION_DIRIGEANT_2FA,
          ],
        },
        amr: { essential: true },
      },
    },
  }),
);

app.get(CALLBACK_URL, async (req, res, next) => {
  try {
    if (req.query.error) {
      throw new client.AuthorizationResponseError(
        `${req.query.error} - ${req.query.error_description}`,
        { cause: currentUrl.searchParams },
      );
    }
    const config = await getProviderConfig();
    const currentUrl = getCurrentUrl(req);
    const tokens = await client.authorizationCodeGrant(
      config,
      currentUrl,
      {
        expectedNonce: req.session.nonce,
        expectedState: req.session.state,
      },
      configOptions,
    );

    req.session.nonce = null;
    req.session.state = null;
    const claims = tokens.claims();
    req.session.userinfo = await client.fetchUserInfo(
      config,
      tokens.access_token,
      claims.sub,
      configOptions,
    );

    console.dir({ userinfo }, { depth: 6 });

    req.session.idtoken = claims;
    req.session.id_token_hint = tokens.id_token;
    req.session.oauth2token = tokens;
    res.redirect("/");
  } catch (e) {
    next(e);
  }
});

app.get("/logout", async (req, res, next) => {
  try {
    const id_token_hint = req.session?.id_token_hint;
    if (!id_token_hint) {
      req.session.destroy();
      return res.redirect("/");
    }

    req.session.destroy();
    const config = await getProviderConfig();
    const redirectUrl = client.buildEndSessionUrl(
      config,
      objToUrlParams({
        post_logout_redirect_uri: `${HOST}/`,
        id_token_hint,
      }),
    );

    res.redirect(redirectUrl);
  } catch (e) {
    next(e);
  }
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  console.dir(err, { depth: 6 });

  res.status(500);
  return res.render("pages/error", {
    error_description: err.message,
    error: err.name,
    title: `Error - ${err.name}`,
  });
});

app.listen(PORT, () => {
  console.log(`App listening on http://localhost:${PORT}`);
});
