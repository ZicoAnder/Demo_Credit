"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.db = void 0;
const knex_1 = __importDefault(require("knex"));
const config_1 = __importDefault(require("../config"));
const knexfile_1 = __importDefault(require("./knexfile"));
const knexInstance = knexfile_1.default[config_1.default.NODE_ENV];
exports.db = (0, knex_1.default)(knexInstance);
//# sourceMappingURL=knexConfig.js.map