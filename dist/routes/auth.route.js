"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRoutes = void 0;
const express_promise_router_1 = __importDefault(require("express-promise-router"));
const controllers_1 = require("../controllers");
const router = (0, express_promise_router_1.default)();
router.route('/register').post(controllers_1.authController.register);
router.route('/login').post(controllers_1.authController.login);
exports.authRoutes = router;
//# sourceMappingURL=auth.route.js.map