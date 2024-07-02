import { Knex } from 'knex';

const tableName = 'transaction_history';

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable(tableName)) {
    return;
  }

  return knex.schema.createTable(tableName, (table) => {
    table.uuid('id').primary().notNullable().defaultTo(knex.raw('(UUID())'));
    table.enu('type', ['DEBIT', 'CREDIT']).notNullable();
    table.bigint('walletId').notNullable();
    table.foreign('walletId').references('walletId').inTable('wallets').onDelete('CASCADE').onUpdate('CASCADE');
    table.uuid('userId').notNullable();
    table.foreign('userId').references('id').inTable('users').onDelete('CASCADE').onUpdate('CASCADE');
    table.double('amount').notNullable();
    table.string('from').nullable();
    table.string('to').nullable();
    table.timestamps(true, true);
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists(tableName);
}
