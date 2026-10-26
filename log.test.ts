import { deepStrictEqual } from "node:assert/strict";
import { test } from "node:test";
import { exception_attributes } from "./log.ts";

const error_with = ({
  cause,
  code,
  message,
  name,
}: {
  cause?: unknown;
  code?: string;
  message: string;
  name: string;
}) => {
  const error = Object.assign(new Error(message, { cause }), { code });
  error.name = name;
  error.stack = `${name} stack`;
  return error;
};

await test("unrolls the cause chain and classifies by the first error code", () => {
  const root = error_with({
    cause: { parameters: "response body, never logged" },
    code: "OAUTH_INVALID_RESPONSE",
    message: 'response parameter "iss" (issuer) missing',
    name: "OperationProcessingError",
  });
  const wrapper = error_with({
    cause: root,
    message: "invalid response encountered",
    name: "ClientError",
  });

  deepStrictEqual(exception_attributes(wrapper), {
    "error.type": "OAUTH_INVALID_RESPONSE",
    "exception.causes": [
      {
        message: 'response parameter "iss" (issuer) missing',
        type: "OperationProcessingError",
      },
    ],
    "exception.message": "invalid response encountered",
    "exception.stacktrace": "ClientError stack",
    "exception.type": "ClientError",
  });
});

await test("falls back to the error name when no link has a code", () => {
  deepStrictEqual(
    exception_attributes(error_with({ message: "boom", name: "TypeError" })),
    {
      "error.type": "TypeError",
      "exception.causes": [],
      "exception.message": "boom",
      "exception.stacktrace": "TypeError stack",
      "exception.type": "TypeError",
    },
  );
});

await test("stops on a cause cycle", () => {
  const error = error_with({ message: "loop", name: "Error" });
  error.cause = error;

  deepStrictEqual(exception_attributes(error)["exception.causes"], []);
});
