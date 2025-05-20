import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const OVToken = buildModule("OVToken", (m) => {
  const token = m.contract("OVToken", []);
//   call the method min with 
  return { token };
});

export default OVToken;
