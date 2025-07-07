FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
  wget gpg software-properties-common lsb-release curl \
  build-essential libboost-all-dev libgmp-dev libssl-dev \
  git netcat-traditional \
  && rm -rf /var/lib/apt/lists/*
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
RUN echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ noble main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null
RUN apt-get update && apt-get install -y kitware-archive-keyring cmake && rm -rf /var/lib/apt/lists/*

RUN wget -qO- https://astral.sh/uv/install.sh | sh
ENV NVM_DIR /root/.nvm
ENV NODE_VERSION 20.14.0
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
RUN . $NVM_DIR/nvm.sh && nvm install $NODE_VERSION && nvm use --delete-prefix $NODE_VERSION
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

WORKDIR /app
RUN git clone https://github.com/OpenVectorAI/cofhe.git
RUN git clone https://github.com/OpenVectorAI/pycofhe.git
RUN git clone https://github.com/openvectorai/openvector_coprocesssor.git --branch tee --single-branch
RUN git clone https://github.com/openvectorai/http_relayer.git

WORKDIR /app/cofhe
RUN git submodule update --init --recursive
RUN mkdir build && cd build && \
  cmake -DCMAKE_INSTALL_PREFIX=. .. && \
  make cofhe_examples -j8 && \
  cp ../scripts/start_network.sh ./examples/ && \
  chmod u+x ./examples/start_network.sh

ENV PATH /root/.local/bin:$PATH
WORKDIR /app/pycofhe
RUN git submodule update --init --recursive
RUN uv sync && uv build

WORKDIR /app/openvector_coprocesssor/backend
RUN uv remove pycofhe
RUN uv sync
RUN uv add /app/pycofhe/dist/*.whl

WORKDIR /app/http_relayer
RUN uv remove pycofhe
RUN uv sync
RUN uv add /app/pycofhe/dist/*.whl


WORKDIR /app/openvector_coprocesssor/frontend/eth_sol
RUN npm install
RUN sed -i.bak '/base_sepolia: {/,/},/c\
localhost :{\
       url: "http://cofhe_final_0:8545"\
}' hardhat.config.ts 
RUN cat hardhat.config.ts
RUN npx hardhat compile
EXPOSE 4455 4456 4457 4458 8001 8002

WORKDIR /app

COPY <<EOF starter.sh
#!/bin/bash
set -e

echo "Sourcing NVM (Node Version Manager)..."
. "$NVM_DIR/nvm.sh"
echo "Sourcing UV environment..."
. "\$HOME/.local/bin/env"


echo "[1/5]Starting CoFHE Network..."
cd /app/cofhe/build/examples/
sed -i 's/"setup_node" "127.0.0.1" "4455"/"setup_node" "0.0.0.0" "4455"/' start_network.sh
sed -i 's/"127.0.0.1" "4455"/"cofhe_final_0" "4455"/g' start_network.sh
sed -i 's/"127.0.0.1"/"0.0.0.0"/g' start_network.sh
./start_network.sh
sleep 3
./tutorial "127.0.0.1" "4476" "cofhe_final_0" "4455"

echo "--- [2/5] Starting HTTP Relayer... ---"
cd /app/http_relayer
cp /app/cofhe/build/examples/server.pem .
cat <<\EOF > .env
CLIENT_IP = 127.0.0.1
CLIENT_PORT = 4478
SETUP_NODE_IP = cofhe_final_0
SETUP_NODE_PORT = 4455
CERT_FILE_PATH = server.pem
\EOF
nohup uv run uvicorn src.openvector_http_to_tcp_relayer.main:app --host 0.0.0.0 --port 8001 > relayer_output.log 2>&1 &

echo "--- [3/5] Starting Hardhat Node... ---"
cd /app/openvector_coprocesssor/frontend/eth_sol
nohup npx hardhat node --hostname 0.0.0.0 --port 8545 > hardhat_node.log 2>&1 &
echo "Waiting for Hardhat node to initialize..."
sleep 3

echo "--- [4/5] Deploying Smart Contracts... ---"
npx hardhat ignition deploy ignition/modules/openvector.ts --network localhost
npx hardhat ignition deploy ignition/modules/ov_token.ts --network localhost
npx hardhat ignition deploy ignition/modules/cov_token.ts --network localhost
echo "Contracts deployed."

echo "--- [5/5] Starting Coprocessor Backend (Foreground Process)... ---"
cd /app/openvector_coprocesssor/backend
# Edit config to listen on all interfaces instead of just localhost
sed -i 's/"host": "127.0.0.1"/"host": "0.0.0.0"/' ./artifacts/example_config.local.json
sed -i 's/"port": 8003/"port": 8002/' ./artifacts/example_config.local.json

nohup uv run python -m openvector_cofhe_coprocessor_backend ./artifacts/example_config.local.json > backend_output.log 2>&1 &

# Keep the container running by watching the hardhat node logs.
echo "--- ############################## ############################## ---"
echo "--- ############################## ############################## ---"
echo "--- All services started. ---"
echo "--- Tailing logs for debugging ---"
echo "--- ############################## ############################## ---"
echo "--- ############################## ############################## ---"
echo "--- Setup Node logs ---"
cat /app/cofhe/build/examples/setup_node.log
echo "--- ############################## ############################## ---"
echo "--- CoFHE Node 4456 logs ---"
cat /app/cofhe/build/examples/cofhe_node_4456.log
echo "--- ############################## ############################## ---"
echo "--- CoFHE Node 4457 logs ---"
cat /app/cofhe/build/examples/cofhe_node_4457.log
echo "--- ############################## ############################## ---"
echo "--- CoFHE Node 4458 logs ---"
cat /app/cofhe/build/examples/cofhe_node_4458.log
echo "--- ############################## ############################## ---"
echo "--- Compute Node logs ---"
cat /app/cofhe/build/examples/compute_node.log
echo "--- ############################## ############################## ---"
echo "--- HTTP Relayer logs ---"
cat /app/http_relayer/relayer_output.log
echo "--- ############################## ############################## ---"
echo "--- Backend logs ---"
cat /app/openvector_coprocesssor/backend/backend_output.log
echo "--- ############################## ############################## ---"
echo "--- Hardhat Node logs ---"
cat /app/openvector_coprocesssor/frontend/eth_sol/hardhat_node.log
echo "--- Starting log tailing for Hardhat Node... ---"
tail -f /app/openvector_coprocesssor/frontend/eth_sol/hardhat_node.log

EOF
RUN chmod +x starter.sh
CMD ["/app/starter.sh"]
