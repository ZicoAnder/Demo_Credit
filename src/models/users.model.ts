export enum ROLE {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

export interface USER {
  id?: string;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  role?: ROLE;
}
