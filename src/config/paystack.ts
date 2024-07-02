import fetch from 'node-fetch';
import config from './';
import { Err, PayData } from '../models';

const SECRET = `Bearer ${config.PAYSTACK_SECRET}`;

export const initializePayment = async (data: PayData) => {
  try {
    const response = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      body: JSON.stringify(data),
      headers: {
        Authorization: SECRET,
        'content-type': 'application/json',
        'cache-control': 'no-cache',
      },
    });

    const resData = await response.json();
    return resData;
  } catch (err: any) {
    const error: Err = new Error('Failed to initialize payment. Please try again');
    error.statusCode = 502;
    throw error;
  }
};
