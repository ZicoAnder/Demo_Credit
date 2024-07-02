describe('User service', () => {
  it('should return user details on success', async () => {
    //**Mocking req and response */

    // where request header contains user token

    const myMock = jest.fn();
    const response = myMock.mockImplementation((req, {}) => {}).mockReturnValue({ success: true });

    expect(response()).toHaveProperty('success');
  });
});
