"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initializePayment = void 0;
const node_fetch_1 = __importDefault(require("node-fetch"));
const _1 = __importDefault(require("./"));
const SECRET = `Bearer ${_1.default.PAYSTACK_SECRET}`;
const initializePayment = (data) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const response = yield (0, node_fetch_1.default)('https://api.paystack.co/transaction/initialize', {
            method: 'POST',
            body: JSON.stringify(data),
            headers: {
                Authorization: SECRET,
                'content-type': 'application/json',
                'cache-control': 'no-cache',
            },
        });
        const resData = yield response.json();
        return resData;
    }
    catch (err) {
        const error = new Error('Failed to initialize payment. Please try again');
        error.statusCode = 502;
        throw error;
    }
});
exports.initializePayment = initializePayment;
//# sourceMappingURL=paystack.js.map