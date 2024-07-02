import bcrypt from 'bcrypt';

export const mockUser1 = {
  id: '123',
  firstName: 'test 1',
  lastName: 'user ',
  email: 'testuser@email.com',
  password: bcrypt.hashSync('password', 12),
};

export const mockUser2 = {
  id: '1234',
  firstName: 'testt 2',
  lastName: 'user 2',
  email: 'testuser22@email.com',
  password: bcrypt.hashSync('password', 12),
};
