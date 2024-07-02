import expressPromise from 'express-promise-router';

import { userController } from '../controllers';
import { authMiddleware } from '../middlewares';

const router = expressPromise();

router.route('/').get(authMiddleware.auth, userController.getUser);

export const userRoutes = router;
