INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT role_id, 'ff.parameter', ARRAY(SELECT a FROM unnest(actions) a WHERE a IN ('read', 'create', 'update', 'delete')) FROM auth.role_grant WHERE menu = 'pm.systemParameter'
ON CONFLICT (role_id, menu) DO NOTHING;
DELETE FROM auth.role_grant WHERE menu = 'pm.systemParameter';
