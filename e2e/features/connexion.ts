//

import { Given, Then, When } from "@badeball/cypress-cucumber-preprocessor";

//

Given("je navigue sur la page", () => {
  cy.visit("/");
});

When("je clique sur le bouton ProConnect", () => {
  cy.get(".proconnect-button").click();
});

When("je suis redirigé sur {string}", (path: string) => {
  cy.url().should("contain", path);
});

Then("je vois {string}", function (text: string) {
  cy.contains(text);
});

//

When("je vois {string} sur ProConnect", (_text: string) => {
  cy.origin(Cypress.env("PC_PROVIDER"), { args: _text }, (text) => {
    cy.contains(text);
  });
});

When("je clique sur {string} sur ProConnect", (_text: string) => {
  cy.origin(Cypress.env("PC_PROVIDER"), { args: _text }, (text) => {
    cy.contains(text).click();
  });
});

When(
  "je me connecte en tant que user@yopmail.com sur ProConnect",
  (path: string) => {
    cy.origin(Cypress.env("PC_PROVIDER"), () => {
      cy.get('[name="login"]').type("user@yopmail.com");
      cy.get('[type="submit"]').click();

      cy.get('[name="password"]').type("user@yopmail.com");
      cy.get('[action="/users/sign-in"]  [type="submit"]')
        .contains("S’identifier")
        .click();
    });
  },
);
