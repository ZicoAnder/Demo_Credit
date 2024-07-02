"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateWithdrawalPayload = exports.validatetransferPayload = exports.validatePayData = exports.validateAccountUpdate = void 0;
const joi_1 = __importDefault(require("joi"));
const validateAccountUpdate = (updateParams) => {
    return joi_1.default.object({
        accountName: joi_1.default.string().trim().required(),
        accountNo: joi_1.default.string().trim().required(),
        bankName: joi_1.default.string().required(),
    }).validate(updateParams);
};
exports.validateAccountUpdate = validateAccountUpdate;
const validatePayData = (data) => {
    return joi_1.default.object({
        amount: joi_1.default.number().required(),
    }).validate(data);
};
exports.validatePayData = validatePayData;
const validatetransferPayload = (data) => {
    return joi_1.default.object({
        amount: joi_1.default.number().required(),
        walletId: joi_1.default.number().required(),
    }).validate(data);
};
exports.validatetransferPayload = validatetransferPayload;
const validateWithdrawalPayload = (data) => {
    return joi_1.default.object({
        amount: joi_1.default.number().required(),
    }).validate(data);
};
exports.validateWithdrawalPayload = validateWithdrawalPayload;
//# sourceMappingURL=wallet.validator.js.map