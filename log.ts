type Severity = "DEBUG" | "ERROR" | "FATAL" | "INFO" | "WARN";

const max_cause_depth = 10;

export const log_event = ({
  attributes,
  name,
  severity,
}: {
  attributes: Record<string, unknown>;
  name: string;
  severity: Severity;
}) => {
  try {
    process.stdout.write(
      `${JSON.stringify({
        timestamp: new Date().toISOString(),
        severity,
        "event.name": name,
        ...attributes,
      })}\n`,
    );
  } catch {
    process.stderr.write(`${severity} ${name}: log event not serializable\n`);
  }
};

export const exception_attributes = (error: Error) => {
  const chain: Error[] = [];
  let link: unknown = error;
  while (
    link instanceof Error &&
    chain.length < max_cause_depth &&
    !chain.includes(link)
  ) {
    chain.push(link);
    link = link.cause;
  }
  const first_code = chain
    .map((cause) =>
      "code" in cause && typeof cause.code === "string"
        ? cause.code
        : undefined,
    )
    .find((code) => code !== undefined);

  return {
    "error.type": first_code ?? error.name,
    "exception.causes": chain
      .slice(1)
      .map((cause) => ({ message: cause.message, type: cause.name })),
    "exception.message": error.message,
    "exception.stacktrace": error.stack,
    "exception.type": error.name,
  };
};
