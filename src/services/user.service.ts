import { db } from '../database/knexConfig';
import { USER } from '../models';

class UserService {
  private tableName = 'users';

  async getProfile(user: USER) {
    const data = await db<USER>(this.tableName)
      .select('email', 'firstName', 'lastName', 'role', 'id')
      .where({ id: user.id })
      .first();

    return {
      success: true,
      data,
    };
  }
}

export const userService = new UserService();
