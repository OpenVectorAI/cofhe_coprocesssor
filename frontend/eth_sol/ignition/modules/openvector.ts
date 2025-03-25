import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const OpenVectorCOFHEExecutor = buildModule('OpenVectorCOFHEExecutor', (m) => {
  const openvector = m.contract("OpenVectorCOFHEExecutor", []);
  return { openvector };
}
);

export default OpenVectorCOFHEExecutor;
