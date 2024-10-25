import "dotenv/config";
import express from "express";
import { Issuer } from "openid-client";
import session from "express-session";
import morgan from "morgan";
import * as crypto from "crypto";
import bodyParser from "body-parser";

const port = parseInt(process.env.PORT, 10) || 3000;
const origin = `${process.env.HOST}`;
const redirectUri = `${origin}${process.env.CALLBACK_URL}`;

const app = express();

app.set("view engine", "ejs");
app.use(
  session({
    name: "pc_session",
    secret: process.env.SESSION_SECRET,
    rolling: true,
  }),
);
app.use(morgan("combined"));

const removeNullValues = (obj) => Object.entries(obj).reduce((a,[k,v]) => (v ? (a[k]=v, a) : a), {})

const getMcpClient = async () => {
  const mcpIssuer = await Issuer.discover(process.env.PC_PROVIDER);

  return new mcpIssuer.Client({
    client_id: process.env.PC_CLIENT_ID,
    client_secret: process.env.PC_CLIENT_SECRET,
    redirect_uris: [redirectUri],
    response_types: ["code"],
    id_token_signed_response_alg: process.env.PC_ID_TOKEN_SIGNED_RESPONSE_ALG,
    userinfo_signed_response_alg:
      process.env.PC_USERINFO_SIGNED_RESPONSE_ALG || null,
  });
};

const acr_values = process.env.ACR_VALUES
  ? process.env.ACR_VALUES.split(",")
  : null;
const login_hint = process.env.LOGIN_HINT || null;
const scope = process.env.PC_SCOPES;
const AUTHORIZATION_DEFAULT_PARAMS = {
  scope,
  login_hint,
  acr_values,
  claims: {
    id_token: {
      amr: {
        essential: true,
      },
    },
  },
};

app.get("/", async (req, res, next) => {
  try {
    res.render("index", {
      title: process.env.SITE_TITLE,
      stylesheet_url: process.env.STYLESHEET_URL,
      userinfo: JSON.stringify(req.session.userinfo, null, 2),
      idtoken: JSON.stringify(req.session.idtoken, null, 2),
      oauth2token: JSON.stringify(req.session.oauth2token, null, 2),
      defaultParamsValue: JSON.stringify(AUTHORIZATION_DEFAULT_PARAMS, null, 2),
      showBetaFeatures: process.env.SHOW_BETA_FEATURES === "True",
    });
  } catch (e) {
    next(e);
  }
});

const getAuthorizationControllerFactory = (extraParams) => {
  return async (req, res, next) => {
    try {
      const client = await getMcpClient();
      const nonce = crypto.randomBytes(16).toString("hex");
      const state = crypto.randomBytes(16).toString("hex");

      req.session.state = state;
      req.session.nonce = nonce;

      const redirectUrl = client.authorizationUrl(removeNullValues({
        nonce,
        state,
        ...AUTHORIZATION_DEFAULT_PARAMS,
        ...extraParams,
      }));

      res.redirect(redirectUrl);
    } catch (e) {
      next(e);
    }
  };
};

app.post("/login", getAuthorizationControllerFactory());

app.post(
  "/select-organization",
  getAuthorizationControllerFactory({
    prompt: "select_organization",
  }),
);

app.post(
  "/update-userinfo",
  getAuthorizationControllerFactory({
    prompt: "update_userinfo",
  }),
);

app.post(
  "/force-login",
  getAuthorizationControllerFactory({
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
  getAuthorizationControllerFactory({
    claims: {
      id_token: {
        amr: { essential: true },
        acr: { essential: true, value: process.env.ACR_VALUE_FOR_2FA },
      },
    },
  }),
);

app.post(
  "/custom-connection",
  bodyParser.urlencoded({ extended: false }),
  (req, res, next) => {
    const customParams = JSON.parse(req.body['custom-params'])

    return getAuthorizationControllerFactory(customParams)(req, res, next);
  },
);

app.get(process.env.CALLBACK_URL, async (req, res, next) => {
  try {
    const client = await getMcpClient();
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(redirectUri, params, {
      nonce: req.session.nonce,
      state: req.session.state,
    });

    req.session.nonce = null;
    req.session.state = null;
    req.session.userinfo = await client.userinfo(tokenSet.access_token);
    req.session.idtoken = tokenSet.claims();
    req.session.id_token_hint = tokenSet.id_token;
    req.session.oauth2token = tokenSet;
    res.redirect("/");
  } catch (e) {
    next(e);
  }
});

app.post("/logout", async (req, res, next) => {
  try {
    const id_token_hint = req.session.id_token_hint;
    req.session.destroy();
    const client = await getMcpClient();
    const redirectUrl = client.endSessionUrl({
      post_logout_redirect_uri: `${origin}/`,
      id_token_hint,
    });

    res.redirect(redirectUrl);
  } catch (e) {
    next(e);
  }
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
  console.log(process.env);
});
