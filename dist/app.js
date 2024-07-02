"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const morgan_1 = __importDefault(require("morgan"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const handlers_1 = require("./handlers");
const config_1 = __importDefault(require("./config"));
const routes_1 = require("./routes");
const app = (0, express_1.default)();
const apiVersion = config_1.default.API_VERSION || 'v1';
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
app.use((0, morgan_1.default)('dev'));
app.use((0, cors_1.default)());
app.use((0, helmet_1.default)());
app.disable('x-powered-by');
app.use(`/api/${apiVersion}/auth`, routes_1.authRoutes);
app.use(`/api/${apiVersion}/wallet`, routes_1.walletRoutes);
app.use(`/api/${apiVersion}/users`, routes_1.userRoutes);
app.use(`/api/${apiVersion}/transactions`, routes_1.transactionRoutes);
//error handler
app.use(handlers_1.ErrorHandler.error);
exports.default = app;
//# sourceMappingURL=app.js.map