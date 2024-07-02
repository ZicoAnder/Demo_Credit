import { Knex } from 'knex';

const tableName = 'wallets';

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable(tableName)) {
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
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists(tableName);
}
