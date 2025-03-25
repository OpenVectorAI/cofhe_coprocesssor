import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { bigint } from "hardhat/internal/core/params/argumentTypes";

const COVToken = buildModule('COVToken', (m) => {
    const token = m.contract("COVToken", []);
    return { token };
    }
);

export default COVToken;