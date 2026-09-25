const createApp = require('./app');

const PORT = process.env.PORT || 3000;
const { app } = createApp();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`================================================================`);
  console.log(` SecureChain DMS - M-of-N Quorum Approval Engine Running`);
  console.log(` Listening on port: ${PORT}`);
  console.log(` Health Check: http://localhost:${PORT}/health`);
  console.log(`================================================================`);
});
