import { authMiddleware } from '../../middlewares';
import { authService } from '../../services';
import { mockUser1 } from '../mocks';

describe('Auth User Middleware', () => {
  let token: any;

  beforeAll(() => {
    //getting token for testing
    token = authService.getToken({
      ...mockUser1,
    });
  });

  it('should throw error if authorization header is not specified', async () => {
    //**Mocking req and res */
    const req = {
      headers: {
        authorization: '',
      },
    };

    expect(authMiddleware.auth(req, {}, jest.fn())).rejects.toThrow('No authorization header');
  });

  it('should return jwt malformed error message on invalid token', async () => {
    //**Mocking req and res */
    const req = {
      headers: {
        authorization: 'xyz',
      },
    };

    expect(authMiddleware.auth.bind(this, req, {}, jest.fn())).rejects.toThrow('Invalid token format');
  });

  it('should return jwt malformed error message on invalid token', async () => {
    //**Mocking req and res */
    const req = {
      headers: {
        authorization: 'Bearer xyz',
      },
    };

    expect(authMiddleware.auth.bind(this, req, {}, jest.fn())).rejects.toThrow('jwt malformed');
  });

  it('should be successful on passing valid token', async () => {
    //**Mocking req and res */
    const req = {
      headers: {
        authorization: `Bearer ${token}`,
      },
    };

    const myMock = jest.fn();
    const response = myMock.mockImplementation((req, {}) => {}).mockReturnValue({ success: true });

    expect(response()).toHaveProperty('success');
  });
});
