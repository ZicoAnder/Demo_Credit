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
Object.defineProperty(exports, "__esModule", { value: true });
exports.transactionService = void 0;
const knexConfig_1 = require("../database/knexConfig");
class WalletTransactionService {
    constructor() {
        this.tableName = 'transaction_history';
    }
    addTransaction(payload) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield (0, knexConfig_1.db)(this.tableName).insert(Object.assign({}, payload));
        });
    }
    transactionHistory(user) {
        return __awaiter(this, void 0, void 0, function* () {
            const transactions = yield (0, knexConfig_1.db)(this.tableName).select().where({ userId: user.id });
            return {
                success: true,
                data: transactions,
            };
        });
    }
}
exports.transactionService = new WalletTransactionService();
//# sourceMappingURL=transaction.service.js.map