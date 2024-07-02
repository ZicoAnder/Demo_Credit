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
const tableName = 'wallets';
function up(knex) {
    return __awaiter(this, void 0, void 0, function* () {
        if (yield knex.schema.hasTable(tableName)) {
            return;
        }
        return knex.schema.createTable(tableName, (table) => {
            table.uuid('id').primary().notNullable().defaultTo(knex.raw('(UUID())'));
            table.bigint('walletId').notNullable().unique(); //serve as user wallet account number
            table.string('userId').notNullable().unique();
            table.foreign('userId').references('id').inTable('users').onDelete('CASCADE').onUpdate('CASCADE');
            table.double('balance').notNullable().defaultTo(0.0);
            table.string('bankName').nullable(); //user bank name for cash withdrawals out of democredit app
            table.string('accountName').nullable(); //user personal account name for cash withdrawals out of democredit app
            table.string('accountNo').nullable(); //user personal account number for cash withdrawals out of democredit app
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
//# sourceMappingURL=20230114224155_wallet.js.map