import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import bodyParser from 'body-parser';
import connectDB from './app/config/db.connect';
import apiRoutes from './app/routes/';


const app = express();

//create corsOptions when hosted online
app.use(cors());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// establish database connection
connectDB();

const PORT = process.env.PORT || 8080;
app.listen(PORT, () =>
    console.log(`Connecting on port ${PORT}...`),
);

//import routes
app.use('/', apiRoutes)


