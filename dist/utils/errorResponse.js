"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorResponse = void 0;
const errorResponse = (message, code = 400) => {
    const error = new Error(message);
    error.statusCode = code;
    throw error;
};
exports.errorResponse = errorResponse;
//# sourceMappingURL=errorResponse.js.map