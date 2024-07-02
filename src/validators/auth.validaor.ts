import Joi from 'joi';

import { USER } from '../models';

export const validateRegisterParams = (registerParams: USER) => {
  return Joi.object({
    firstName: Joi.string().trim().required(),
    lastName: Joi.string().trim().required(),
    email: Joi.string().required().email().normalize(),
    password: Joi.string().min(5).trim().required(),
  }).validate(registerParams);
};

export const validateLoginrParams = (loginParams: USER) => {
  return Joi.object({
    email: Joi.string().required().email().normalize(),
    password: Joi.string().min(5).trim().required(),
  }).validate(loginParams);
};
