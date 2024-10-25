# Publishing docker image

```
docker build -t numerique-gouv/proconnect-test-client .
```

Authenticate to the github docker registery:

https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic

Then

```
docker push ghcr.io/numerique-gouv/proconnect-test-client
```
