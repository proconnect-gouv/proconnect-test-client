import { PageLayout } from "./layout.tsx";

export const NotFoundPage = ({
  path,
  stylesheet_url,
  title,
}: {
  path: string;
  stylesheet_url: string | undefined;
  title: string;
}) => (
  <PageLayout stylesheet_url={stylesheet_url} title={title}>
    <main>
      <h1>{title}</h1>
      <h2>
        Page introuvable : <code>{path}</code>
      </h2>
      <a href="/">Retour à l’accueil</a>
    </main>
  </PageLayout>
);
