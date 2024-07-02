import { db } from '../database/knexConfig';
import { TRANSACTION, USER } from '../models';

class WalletTransactionService {
  private tableName = 'transaction_history';

  async addTransaction(payload: TRANSACTION) {
    return await db<TRANSACTION>(this.tableName).insert({ ...payload });
  }

  async transactionHistory(user: USER) {
    const transactions = await db<TRANSACTION>(this.tableName).select().where({ userId: user.id });
    return {
      success: true,
      data: transactions,
    };
  }
}
export const transactionService = new WalletTransactionService();
