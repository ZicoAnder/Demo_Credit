import { Request } from 'express';
import { USER } from './users.model';

export interface IRequest extends Request {
  user?: USER;
}

export interface Err extends Error {
  statusCode?: number;
  code?: number;
}
