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
exports.userService = void 0;
const knexConfig_1 = require("../database/knexConfig");
class UserService {
    constructor() {
        this.tableName = 'users';
    }
    getProfile(user) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = yield (0, knexConfig_1.db)(this.tableName)
                .select('email', 'firstName', 'lastName', 'role', 'id')
                .where({ id: user.id })
                .first();
            return {
                success: true,
                data,
            };
        });
    }
}
exports.userService = new UserService();
//# sourceMappingURL=user.service.js.map