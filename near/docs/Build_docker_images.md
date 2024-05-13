# Building

## Build docker images
For the example, let's build the images and upload them to the repository on the docker hub.

### Http service

 1. Build docker image:
```bash
docker compose build http_service
```
 2. Tag with new version:
```bash
docker tag zpokendev/zk-lite-client_http-service:latest zpokendev/zk-lite-client_http-service:1.0
```
 3. Push image with version to docker hub:
```bash
docker push zpokendev/zk-lite-client_http-service:1.0
```
 4. Rewrite image with latest tag in docker hub:
```bash
docker push zpokendev/zk-lite-client_http-service:latest
```

### Block proover

 1. Build docker image:
```bash
docker compose build block_prover
```
 2. Tag with new version:
```bash
docker tag zpokendev/zk-lite-client_block-prover:latest zpokendev/zk-lite-client_block-prover:1.0
```
 3. Push image with version to docker hub:
```bash
docker push zpokendev/zk-lite-client_block-prover:1.0
```
 4. Rewrite image with latest tag in docker hub:
```bash
docker push zpokendev/zk-lite-client_block-prover:latest
```

### Sign proover

 1. Build docker image:
```bash
docker compose build zk-lite-client_sign-prover
```
 2. Tag with new version:
```bash
docker tag zpokendev/zk-lite-client_sign-prover:latest zpokendev/zk-lite-client_sign-prover:1.0
```
 3. Push image with version to docker hub:
```bash
docker push zpokendev/zk-lite-client_sign-prover:1.0
```
 4. Rewrite image with latest tag in docker hub:
```bash
docker push zpokendev/zk-lite-client_sign-prover:latest
```

### Gnark wrapper with prebuilt keys

 1. Change dir to gnark verifier:
```bash
cd ./near/gnark-plonky2-verifier/docker/
```
 2. Build docker image:
```bash
docker build -f ./Dockerfile_gnark_prebuilt . -t zpokendev/zk-lite-client_gnark-wrapper_prebuilt:latest
```
 3. Tag with new version:
```bash
docker tag zpokendev/zk-lite-client_gnark-wrapper_prebuilt:latest zpokendev/zk-lite-client_gnark-wrapper_prebuilt:1.0
```
 4. Push image with version to docker hub:
```bash
docker push zpokendev/zk-lite-client_gnark-wrapper_prebuilt:1.0
```
 5. Rewrite image with latest tag in docker hub:
```bash
docker push zpokendev/zk-lite-client_gnark-wrapper_prebuilt:latest
```

### Gnark keys

 1. Change dir to gnark verifier:
```bash
cd ./near/gnark-plonky2-verifier/docker/
```
 2. Build docker image:
```bash
docker build -f ./Dockerfile_gnark_keys . -t zpokendev/zk-lite-client_gnark-wrapper_keys:latest
```
 3. Tag with new version:
```bash
docker tag zpokendev/zk-lite-client_gnark-wrapper_keys:latest zpokendev/zk-lite-client_gnark-wrapper_keys:1.0
```
 4. Push image with version to docker hub:
```bash
docker push zpokendev/zk-lite-client_gnark-wrapper_keys:1.0
```
 5. Rewrite image with latest tag in docker hub:
```bash
docker push zpokendev/zk-lite-client_gnark-wrapper_keys:latest
```

### Gnark wrapper with new keys

 1. Change dir to gnark verifier:
```bash
cd ./near/gnark-plonky2-verifier/docker/
```
 2. Build docker image:
```bash
docker build -f ./Dockerfile . -t zpokendev/zk-lite-client_gnark-wrapper:latest
```
 3. Tag with new version:
```bash
docker tag zpokendev/zk-lite-client_gnark-wrapper:latest zpokendev/zk-lite-client_gnark-wrapper:1.0
```
 4. Push image with version to docker hub:
```bash
docker push zpokendev/zk-lite-client_gnark-wrapper:1.0
```
 5. Rewrite image with latest tag in docker hub:
```bash
docker push zpokendev/zk-lite-client_gnark-wrapper:latest
```