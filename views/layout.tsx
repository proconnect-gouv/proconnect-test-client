import { raw } from "hono/html";
import type { Child, PropsWithChildren } from "hono/jsx";

export const PageLayout = ({
  children,
  head,
  stylesheet_url,
  title,
}: PropsWithChildren<{
  head?: Child;
  stylesheet_url: string | undefined;
  title: string;
}>) => (
  <>
    {raw("<!doctype html>")}
    <html lang="fr-FR">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width" />
        <meta name="robots" content="noindex, nofollow" />
        <title>{title} - ProConnect</title>
        {head}
        <link rel="stylesheet" href={stylesheet_url} />
      </head>
      <body>{children}</body>
    </html>
  </>
);
