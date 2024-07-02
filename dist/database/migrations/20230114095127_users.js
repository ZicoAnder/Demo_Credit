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
exports.down = exports.up = void 0;
const tableName = 'users';
function up(knex) {
    return __awaiter(this, void 0, void 0, function* () {
        if (yield knex.schema.hasTable(tableName)) {
            return;
        }
        return knex.schema.createTable(tableName, (table) => {
            table.uuid('id').primary().notNullable().defaultTo(knex.raw('(UUID())'));
            table.string('firstName', 100).notNullable();
            table.string('lastName', 100).notNullable();
            table.string('email').unique().notNullable();
            table.string('password').notNullable();
            table.enu('role', ['USER', 'ADMIN']).defaultTo('USER').notNullable();
            table.timestamps(true, true);
        });
    });
}
exports.up = up;
function down(knex) {
    return __awaiter(this, void 0, void 0, function* () {
        return knex.schema.dropTableIfExists(tableName);
    });
}
exports.down = down;
//# sourceMappingURL=20230114095127_users.js.map