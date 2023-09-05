docker build -t pepc-boost-builder .;
docker tag pepc-boost-builder:latest public.ecr.aws/t1d5h1w5/pepc-boost-builder:latest;
docker push public.ecr.aws/t1d5h1w5/pepc-boost-builder:latest;