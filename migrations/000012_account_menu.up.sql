-- Bagan Akun (COA) in Portal Master: a role keeps on it what it can do on Kode Biaya, which now points to accounts.
INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT role_id, 'pm.account', actions FROM auth.role_grant WHERE menu = 'pm.charge'
ON CONFLICT (role_id, menu) DO NOTHING;
