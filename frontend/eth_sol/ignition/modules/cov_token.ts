import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const COVToken = buildModule("COVToken", (m) => {
  const token = m.contract("COVToken", []);
  return { token };
});

export default COVToken;
