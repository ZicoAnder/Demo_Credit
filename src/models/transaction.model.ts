export enum TransactionType {
  DEBIT = 'DEBIT',
  CREDIT = 'CREDIT',
}

export interface TRANSACTION {
  type: TransactionType;
  amount: number;
  userId: string;
  walletId: number;
  from?: string;
  to: string;
}
