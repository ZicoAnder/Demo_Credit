"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateLoginrParams = exports.validateRegisterParams = void 0;
const joi_1 = __importDefault(require("joi"));
const validateRegisterParams = (registerParams) => {
    return joi_1.default.object({
        firstName: joi_1.default.string().trim().required(),
        lastName: joi_1.default.string().trim().required(),
        email: joi_1.default.string().required().email().normalize(),
        password: joi_1.default.string().min(5).trim().required(),
    }).validate(registerParams);
};
exports.validateRegisterParams = validateRegisterParams;
const validateLoginrParams = (loginParams) => {
    return joi_1.default.object({
        email: joi_1.default.string().required().email().normalize(),
        password: joi_1.default.string().min(5).trim().required(),
    }).validate(loginParams);
};
exports.validateLoginrParams = validateLoginrParams;
//# sourceMappingURL=auth.validaor.js.map