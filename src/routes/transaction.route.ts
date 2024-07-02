import expressPromise from 'express-promise-router';

import { transactionController } from '../controllers';
import { authMiddleware } from '../middlewares';

const router = expressPromise();

router.route('/').get(authMiddleware.auth, transactionController.getUserWalletTransactions);

export const transactionRoutes = router;
