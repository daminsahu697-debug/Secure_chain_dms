const { Pool } = require('pg');
const pool = new Pool({ 
  connectionString: 'postgresql://postgres.buvjudpqfzscxoeqwnay:Securechaindms%40123@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres' 
});

async function main() {
  // Show recent edit_requests in quorum engine DB 
  const stale = await pool.query("SELECT id, status FROM edit_requests ORDER BY id DESC LIMIT 10");
  console.log('Recent edit_requests:', JSON.stringify(stale.rows, null, 2));
  
  // Show approval_assignments
  const aa = await pool.query("SELECT aa.edit_request_id, aa.approver_id, aa.status FROM approval_assignments aa LIMIT 30");
  console.log('Recent approval_assignments:', JSON.stringify(aa.rows, null, 2));
}

main().then(() => pool.end()).catch(e => { console.error(e.message, e.stack); pool.end(); });
