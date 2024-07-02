import knex, { Knex } from 'knex';

import config from '../config';
import knexConfig from './knexfile';

const knexInstance: Knex.Config = knexConfig[config.NODE_ENV];

export const db = knex(knexInstance);
