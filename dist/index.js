"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const app_1 = __importDefault(require("./app"));
const config_1 = __importDefault(require("./config"));
const PORT = config_1.default.PORT || 5000;
app_1.default.listen(PORT, () => console.log(`server running on PORT:: 🚀💥>>> ${PORT}`));
//# sourceMappingURL=index.js.map