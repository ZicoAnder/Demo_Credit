import bcrypt from 'bcrypt';
import JWT from 'jsonwebtoken';
import config from '../config';

import { db } from '../database/knexConfig';
import { USER } from '../models';
import { errorResponse } from '../utils';
import { validateLoginrParams, validateRegisterParams } from '../validators';
import { walletService } from './wallet.service';
import axios from 'axios';

export class AuthService {
  private tableName = 'users';

  private async isUserBlacklisted(userDetails: USER): Promise<boolean> {
    const apiURL = process.env.LENDSQR_API_URL || 'default_api_url'; // Placeholder URL
    const apiKey = process.env.LENDSQR_API_KEY || 'default_api_key';
    try {
      const response = await axios.post(apiURL, userDetails, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      // Assuming the API returns { isBlacklisted: true/false }
      return response.data.isBlacklisted;
    } catch (error) {
      console.error('Error checking blacklist status:', error);
      throw new Error('Failed to check blacklist status');
    }
  }

  async register(body: USER) {
    const { error } = validateRegisterParams(body);

    //check for errors in body data
    if (error) {
      return errorResponse(error.details[0].message, 400);
    }

    // Check if the user is blacklisted before proceeding
    const isBlacklisted = await this.isUserBlacklisted(body);
    if (isBlacklisted) {
      return errorResponse('User is blacklisted', 403); // Forbidden
    }

    const { firstName, lastName, email, password } = body;

    //make email lowercase
    const formattedEmail = this.formatEmail(email);

    //check if email is already in use
    const isEmail = await this.findUserByEmail(formattedEmail);
    if (isEmail) {
      return errorResponse('Email already in use', 400);
    }

    //hash password
    const hashPassword = await this.hashPassword(password);

    await db<USER>(this.tableName).insert({ firstName, lastName, password: hashPassword, email: formattedEmail });

    //on creating user, create wallet for user
    await walletService.createWallet((await this.findUserByEmail(formattedEmail))!.id!);

    return {
      success: true,
      message: 'Account successfully created',
    };
  }

  async login(body: USER) {
    const { error } = validateLoginrParams(body);
    if (error) {
      return errorResponse(error.details[0].message, 400);
    }

    const { email, password } = body;

    //transform email to lowercase
    const formattedEmail = this.formatEmail(email);

    //check if email is correct
    const user = await db<USER>(this.tableName).where({ email: formattedEmail }).first();
    if (!user) {
      return errorResponse('Email or Password is incorrect', 400);
    }

    //check if password is correct
    const isPassword = await bcrypt.compare(password, user.password);
    if (!isPassword) {
      return errorResponse('Email or Password is incorrect', 400);
    }

    //getToken
    const token = this.getToken(user);

    return {
      success: true,
      message: 'Login successful',
      data: token,
    };
  }

  async findUserByEmail(email: string) {
    return await db<USER>(this.tableName).where({ email }).first();
  }

  async hashPassword(password: string) {
    const salt = await bcrypt.genSalt(12);
    return await bcrypt.hash(password, salt);
  }

  formatEmail(email: string) {
    return email.toLowerCase();
  }

  getToken(user: USER) {
    return JWT.sign(
      {
        iat: Date.now(),
        iss: 'Democredit',
        userId: user.id,
      },
      config.SECRET_KEY,
      { expiresIn: '48h' },
    );
  }
}

export const authService = new AuthService();
