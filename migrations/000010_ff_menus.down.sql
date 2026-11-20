-- Operation grants go back to Bill of Lading; Job Sheet keeps read/export.
INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT role_id, 'ff.bl', actions FROM auth.role_grant WHERE menu = 'ff.operation'
ON CONFLICT (role_id, menu) DO NOTHING;
DELETE FROM auth.role_grant WHERE menu = 'ff.operation';
