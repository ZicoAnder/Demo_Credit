"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.userRoutes = void 0;
const express_promise_router_1 = __importDefault(require("express-promise-router"));
const controllers_1 = require("../controllers");
const middlewares_1 = require("../middlewares");
const router = (0, express_promise_router_1.default)();
router.route('/').get(middlewares_1.authMiddleware.auth, controllers_1.userController.getUser);
exports.userRoutes = router;
//# sourceMappingURL=user.route.js.map