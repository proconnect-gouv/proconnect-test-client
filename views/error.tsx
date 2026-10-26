import { PageLayout } from "./layout.tsx";

export const ErrorPage = ({
  error,
  error_description,
  request_id,
  stylesheet_url,
  title,
}: {
  error: string;
  error_description: string;
  request_id: string;
  stylesheet_url: string | undefined;
  title: string;
}) => (
  <PageLayout stylesheet_url={stylesheet_url} title={title}>
    <main>
      <h1>{title}</h1>
      <h2>
        Erreur <code>{error}</code>
      </h2>
      <blockquote>{error_description}</blockquote>
      <p>
        Identifiant de la requête : <code>{request_id}</code>
      </p>
      <a href="/">Retour à l’accueil</a>
    </main>
  </PageLayout>
);
