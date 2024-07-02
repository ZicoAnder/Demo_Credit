import expressPromise from 'express-promise-router';

import { authController } from '../controllers';

const router = expressPromise();

router.route('/register').post(authController.register);
router.route('/login').post(authController.login);

export const authRoutes = router;
