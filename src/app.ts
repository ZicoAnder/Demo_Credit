import express, { Application } from 'express';
import morgan from 'morgan';
import cors from 'cors';
import helmet from 'helmet';

import { ErrorHandler } from './handlers';
import config from './config';
import { authRoutes, transactionRoutes, userRoutes, walletRoutes } from './routes';

const app: Application = express();
const apiVersion = config.API_VERSION || 'v1';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(cors());
app.use(helmet());
app.disable('x-powered-by');

app.use(`/api/${apiVersion}/auth`, authRoutes);
app.use(`/api/${apiVersion}/wallet`, walletRoutes);
app.use(`/api/${apiVersion}/users`, userRoutes);
app.use(`/api/${apiVersion}/transactions`, transactionRoutes);

//error handler
app.use(ErrorHandler.error);

export default app;
