import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import appRoutes from './routes/apps';
import communityRoutes from './routes/communities';
import memberRoutes from './routes/members';
import pool from './services/database';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// Routes
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'opensocial-api'
  });
});

app.use('/api/v1/apps', appRoutes);
app.use('/api/v1/communities', communityRoutes);
app.use('/api/v1/communities', memberRoutes);

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
async function start() {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connected');
    
    app.listen(PORT, () => {
      console.log(`✅ OpenSocial API running on port ${PORT}`);
      console.log(`   Health check: http://localhost:${PORT}/health`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

start();
