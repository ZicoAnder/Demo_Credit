"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.walletRoutes = void 0;
const express_promise_router_1 = __importDefault(require("express-promise-router"));
const config_1 = __importDefault(require("../config"));
const controllers_1 = require("../controllers");
const middlewares_1 = require("../middlewares");
const router = (0, express_promise_router_1.default)();
router
    .route('/')
    .get(middlewares_1.authMiddleware.auth, controllers_1.walletController.getUserWallet)
    .patch(middlewares_1.authMiddleware.auth, controllers_1.walletController.updateWalletInfo);
router.route('/fund').post(middlewares_1.authMiddleware.auth, controllers_1.walletController.fundWallet);
// endpoint for wallet funding payment verification and balance update hidden (for test use: '/webhook-verify')
router.route(config_1.default.WEBHOOK_URL).post(controllers_1.walletController.verifyPayment);
router.route('/transfers').post(middlewares_1.authMiddleware.auth, controllers_1.walletController.transferFunds);
router.route('/withdrawals').post(middlewares_1.authMiddleware.auth, controllers_1.walletController.withdrawFunds);
exports.walletRoutes = router;
//# sourceMappingURL=wallet.route.js.map