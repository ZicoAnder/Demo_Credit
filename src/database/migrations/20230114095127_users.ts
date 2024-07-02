import { Knex } from 'knex';

const tableName = 'users';

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable(tableName)) {
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
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists(tableName);
}
