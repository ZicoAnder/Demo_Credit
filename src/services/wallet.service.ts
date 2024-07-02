import { initializePayment } from '../config/paystack';
import { db } from '../database/knexConfig';
import {
  AccountInfo,
  PayData,
  TRANSACTION,
  TransactionType,
  TransferPayload,
  USER,
  WALLET,
  WithdrawalPayload,
} from '../models';
import { errorResponse, minimumAmount } from '../utils';
import {
  validateAccountUpdate,
  validatePayData,
  validatetransferPayload,
  validateWithdrawalPayload,
} from '../validators';
import { authService } from './auth.service';
import { transactionService } from './transaction.service';

class WalletService {
  private tableName = 'wallets';

  async createWallet(userId: string) {
    const walletId = await this.generateWalletId();

    return await db<WALLET>(this.tableName).insert({ userId, walletId });
  }

  async generateWalletId() {
    const min = 19999999999;
    const max = 39999999999;

    while (true) {
      const walletId = Math.floor(Math.random() * (max - min + 1) + min);

      //check if generated id already belongs to a user
      const walletIdExist = await db<WALLET>(this.tableName).where({ walletId }).first();
      if (!walletIdExist) {
        return walletId;
      }
    }
  }

  async getWallet(user: USER) {
    const wallet = await db<WALLET>(this.tableName).where({ userId: user.id }).first();
    return {
      success: true,
      data: wallet,
    };
  }

  //update user account name, number, and bank name
  async updateWallet(params: WALLET, user: USER) {
    const { error } = validateAccountUpdate(params);
    if (error) {
      return errorResponse(error.details[0].message, 400);
    }

    const { accountName, accountNo, bankName } = params;

    await db<WALLET>(this.tableName).where({ userId: user?.id }).update({ accountName, accountNo, bankName });

    return { success: true, message: 'Account details successfully updated' };
  }

  async fundWallet(body: PayData, user: USER) {
    const { error } = validatePayData(body);
    if (error) {
      return errorResponse(error.details[0].message, 400);
    }

    const { amount } = body;
    if (amount < minimumAmount) {
      return errorResponse(`Invalid transaction amount. Minimum #${minimumAmount}`, 400);
    }

    const data = await initializePayment({ email: user?.email, amount: amount * 100 });

    return {
      status: true,
      message: 'Payment successfully initialised',
      data,
    };
  }

  //verify payment using paystack webhook
  async webHookVerifyPyment(body: any) {
    const { data } = body;

    const email = data?.customer?.email;

    // check if payment was successful
    if (email && data?.status === 'success') {
      // get user by email
      const user = await authService.findUserByEmail(email);

      if (user) {
        const wallet = await db<WALLET>(this.tableName).where({ userId: user.id }).first();

        //update user wallet balance
        await db<WALLET>(this.tableName)
          .where({ userId: user?.id })
          .increment('balance', Math.floor(data?.amount / 100));

        //update wallet transaction history
        await this.saveTransactionHistory(
          TransactionType.CREDIT,
          Math.floor(data?.amount / 100),
          user.id!,
          wallet?.walletId!,
          'Bank',
          'wallet',
        );
      }
    }
  }

  async transferFunds(body: TransferPayload, user: USER) {
    const { error } = validatetransferPayload(body);
    if (error) {
      return errorResponse(error.details[0].message, 400);
    }

    const { amount, walletId } = body;

    if (amount < minimumAmount) {
      return errorResponse(`Invalid transaction amount. Minimum ${minimumAmount}`, 400);
    }

    //validate sender wallet
    const userWallet = await db<WALLET>(this.tableName).where({ userId: user.id }).first();
    if (!userWallet) {
      return errorResponse('Cannot make transfer from this account. Contact support team', 403);
    }

    //validate amount
    if (userWallet.balance < amount) {
      return errorResponse('Insufficient balance.');
    }

    //validate receiver wallet
    const receiverWallet = await db<WALLET>(this.tableName).where({ walletId }).first();
    if (!receiverWallet) {
      return errorResponse('Invalid wallet id.');
    }

    if (receiverWallet.userId === user.id) {
      return errorResponse('Cannot transfer money to self');
    }

    //top up receiver wallet
    await db<WALLET>(this.tableName).where({ walletId }).increment('balance', amount);

    //remove amount from sender wallet
    await db<WALLET>(this.tableName).where({ walletId: userWallet.walletId }).decrement('balance', amount);

    //update sender(user) wallet transaction history
    await this.saveTransactionHistory(
      TransactionType.DEBIT,
      amount,
      user.id!,
      userWallet?.walletId!,
      'me',
      `${receiverWallet.walletId}`,
    );

    //update receiver wallet transaction history
    await this.saveTransactionHistory(
      TransactionType.CREDIT,
      amount,
      receiverWallet.userId,
      receiverWallet?.walletId!,
      `${userWallet.walletId}`,
      'me',
    );

    return { success: true, message: 'Transfer successful', statusCode: 200 };
  }

  async withdrawFunds(body: WithdrawalPayload, user: USER) {
    const { error } = validateWithdrawalPayload(body);
    if (error) {
      return errorResponse(error.details[0].message);
    }

    const { amount } = body;
    if (amount < minimumAmount) {
      return errorResponse(`Invalid transaction amount. Minimum ${minimumAmount}`);
    }

    const userWallet = await db<WALLET>(this.tableName).where({ userId: user.id }).first();
    if (!userWallet) {
      return errorResponse('Cannot make withdrawals from this account. Contact support team', 403);
    }

    //validate amount
    if (userWallet.balance < amount) {
      return errorResponse('Insufficient balance.');
    }

    if (!userWallet.bankName || !userWallet.accountName || !userWallet.accountNo) {
      return errorResponse('Account details (name, bank and number) must be provided before withdrawals.');
    }

    //remove amount from wallet balance
    await db<WALLET>(this.tableName).where({ walletId: userWallet.walletId }).decrement('balance', amount);

    this.demoTransferToBank(userWallet.bankName, userWallet.accountName, userWallet.accountNo);

    //update wallet transaction history
    await this.saveTransactionHistory(
      TransactionType.DEBIT,
      amount,
      userWallet.userId,
      userWallet?.walletId!,
      'democredit',
      `${userWallet.bankName}-${userWallet.accountNo}-${userWallet.accountName}`,
    );

    return { success: true, message: 'Withdrawal successful' };
  }

  async demoTransferToBank(bankName: AccountInfo, accountName: AccountInfo, accountNo: AccountInfo) {
    /***
     * Assumptiosn
     * ================
     * Transfer made to user bank account by admin, thus wallet debited and user bank account credited
     *
     * ***/
    return;
  }

  async saveTransactionHistory(
    type: TransactionType,
    amount: number,
    userId: string,
    walletId: number,
    from: string,
    to: string,
  ) {
    const payload: TRANSACTION = {
      type,
      amount,
      userId,
      walletId,
      from,
      to,
    };
    return await transactionService.addTransaction(payload);
  }
}

export const walletService = new WalletService();
