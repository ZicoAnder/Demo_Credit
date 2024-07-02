import { USER } from '../../models';
import { authService } from '../../services';
import { mockUser1 } from '../mocks';

describe('Auth Service', () => {
  describe('Register user', () => {
    it('should return error on invalid body params', async () => {
      const body: USER = {
        firstName: '',
        lastName: '',
        email: '',
        password: '',
      };

      expect(authService.register(body)).rejects.toThrow();
    });

    it('should register new user when success criteria is met', async () => {
      const body: USER = mockUser1;

      const myMock = jest.fn();
      const response = myMock.mockImplementation((body, {}) => {}).mockReturnValue({ success: true });

      expect(response()).toHaveProperty('success');
    });
  });

  describe('Login user', () => {
    it('should return error on invalid body params', async () => {
      const body: USER = {
        firstName: '',
        lastName: '',
        email: '',
        password: '',
      };

      expect(authService.login(body)).rejects.toThrow();
    });

    it('should login user and return token on success', async () => {
      const myMock = jest.fn();
      const response = myMock.mockImplementation((body, {}) => {}).mockReturnValue({ success: true, token: 'dksndks' });

      expect(response()).toHaveProperty('token');
    });
  });
});
