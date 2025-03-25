import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { bigint } from "hardhat/internal/core/params/argumentTypes";

const OVToken = buildModule('OVToken', (m) => {
    const token = m.contract("OVToken", [10]);
    return { token };
    }
);

export default OVToken;