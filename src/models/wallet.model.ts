export interface WALLET {
  id?: string;
  walletId?: number;
  userId: string;
  balance: number;
  bankName?: string;
  accountName?: string;
  accountNo?: string;
}

export interface PayData {
  email?: string;
  amount: number;
}

export interface TransferPayload {
  amount: number;
  walletId: number; //receiver's wallet ID
}

export interface WithdrawalPayload {
  amount: number;
}

export type AccountInfo = string | undefined;
