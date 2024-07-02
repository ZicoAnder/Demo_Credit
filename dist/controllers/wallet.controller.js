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
exports.walletController = void 0;
const services_1 = require("../services");
class WalletController {
    getUserWallet(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield services_1.walletService.getWallet(req.user);
            return res.status(200).json(Object.assign({}, response));
        });
    }
    //update user account name, number, and bank name
    updateWalletInfo(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield services_1.walletService.updateWallet(req.body, req.user);
            return res.status(200).json(Object.assign({}, response));
        });
    }
    //user funding their wallet
    fundWallet(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield services_1.walletService.fundWallet(req.body, req.user);
            return res.status(200).json(Object.assign({}, response));
        });
    }
    //verify payment upon successful funding of account
    verifyPayment(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            yield services_1.walletService.webHookVerifyPyment(req.body);
            res.sendStatus(200);
        });
    }
    transferFunds(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield services_1.walletService.transferFunds(req.body, req.user);
            return res.status(200).json(Object.assign({}, response));
        });
    }
    withdrawFunds(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield services_1.walletService.withdrawFunds(req.body, req.user);
            return res.status(200).json(Object.assign({}, response));
        });
    }
}
exports.walletController = new WalletController();
//# sourceMappingURL=wallet.controller.js.map