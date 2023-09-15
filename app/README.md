# Images

## Base images

* base: used in devcontainer.
* final: used in deployment

### Build the images

```shell
cd app
# Base
docker build -t nublar.azurecr.io/webca/base --target base -f Dockerfile .
docker push nublar.azurecr.io/webca/base

# Final
docker build -t nublar.azurecr.io/webca/roco-api --target final -f Dockerfile .
docker image tag nublar.azurecr.io/webca/roco-api:latest nublar.azurecr.io/webca/roco-api:testing
docker push nublar.azurecr.io/webca/roco-api:testing
```

### Run containers

```shell
cd deployment
docker run --env-file .\prod\.env.db --name db --network test postgres:14.5-alpine
docker run --env-file .\prod\.env --network test -p 9000:8000 nublar.azurecr.io/webca/roco-api api
```
