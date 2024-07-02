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
exports.authService = exports.AuthService = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const config_1 = __importDefault(require("../config"));
const knexConfig_1 = require("../database/knexConfig");
const utils_1 = require("../utils");
const validators_1 = require("../validators");
const wallet_service_1 = require("./wallet.service");
class AuthService {
    constructor() {
        this.tableName = 'users';
    }
    register(body) {
        return __awaiter(this, void 0, void 0, function* () {
            const { error } = (0, validators_1.validateRegisterParams)(body);
            //check for errors in body data
            if (error) {
                return (0, utils_1.errorResponse)(error.details[0].message, 400);
            }
            const { firstName, lastName, email, password } = body;
            //make email lowercase
            const formattedEmail = this.formatEmail(email);
            //check if email is already in use
            const isEmail = yield this.findUserByEmail(formattedEmail);
            if (isEmail) {
                return (0, utils_1.errorResponse)('Email already in use', 400);
            }
            //hash password
            const hashPassword = yield this.hashPassword(password);
            yield (0, knexConfig_1.db)(this.tableName).insert({ firstName, lastName, password: hashPassword, email: formattedEmail });
            //on creating user, create wallet for user
            yield wallet_service_1.walletService.createWallet((yield this.findUserByEmail(formattedEmail)).id);
            return {
                success: true,
                message: 'Account successfully created',
            };
        });
    }
    login(body) {
        return __awaiter(this, void 0, void 0, function* () {
            const { error } = (0, validators_1.validateLoginrParams)(body);
            if (error) {
                return (0, utils_1.errorResponse)(error.details[0].message, 400);
            }
            const { email, password } = body;
            //transform email to lowercase
            const formattedEmail = this.formatEmail(email);
            //check if email is correct
            const user = yield (0, knexConfig_1.db)(this.tableName).where({ email: formattedEmail }).first();
            if (!user) {
                return (0, utils_1.errorResponse)('Email or Password is incorrect', 400);
            }
            //check if password is correct
            const isPassword = yield bcrypt_1.default.compare(password, user.password);
            if (!isPassword) {
                return (0, utils_1.errorResponse)('Email or Password is incorrect', 400);
            }
            //getToken
            const token = this.getToken(user);
            return {
                success: true,
                message: 'Login successful',
                data: token,
            };
        });
    }
    findUserByEmail(email) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield (0, knexConfig_1.db)(this.tableName).where({ email }).first();
        });
    }
    hashPassword(password) {
        return __awaiter(this, void 0, void 0, function* () {
            const salt = yield bcrypt_1.default.genSalt(12);
            return yield bcrypt_1.default.hash(password, salt);
        });
    }
    formatEmail(email) {
        return email.toLowerCase();
    }
    getToken(user) {
        return jsonwebtoken_1.default.sign({
            iat: Date.now(),
            iss: 'Democredit',
            userId: user.id,
        }, config_1.default.SECRET_KEY, { expiresIn: '48h' });
    }
}
exports.AuthService = AuthService;
exports.authService = new AuthService();
//# sourceMappingURL=auth.service.js.map