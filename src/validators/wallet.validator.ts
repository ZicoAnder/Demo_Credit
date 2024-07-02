import Joi from 'joi';

import { PayData, TransferPayload, WALLET, WithdrawalPayload } from '../models';

export const validateAccountUpdate = (updateParams: WALLET) => {
  return Joi.object({
    accountName: Joi.string().trim().required(),
    accountNo: Joi.string().trim().required(),
    bankName: Joi.string().required(),
  }).validate(updateParams);
};

export const validatePayData = (data: PayData) => {
  return Joi.object({
    amount: Joi.number().required(),
  }).validate(data);
};

export const validatetransferPayload = (data: TransferPayload) => {
  return Joi.object({
    amount: Joi.number().required(),
    walletId: Joi.number().required(),
  }).validate(data);
};

export const validateWithdrawalPayload = (data: WithdrawalPayload) => {
  return Joi.object({
    amount: Joi.number().required(),
  }).validate(data);
};
