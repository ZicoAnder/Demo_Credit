import { Response } from 'express';
import { IRequest } from '../models';
import { transactionService } from '../services';

class WalletTransactionController {
  async getUserWalletTransactions(req: IRequest, res: Response) {
    const response = await transactionService.transactionHistory(req.user!);
    return res.status(200).json({ ...response });
  }
}

export const transactionController = new WalletTransactionController();
