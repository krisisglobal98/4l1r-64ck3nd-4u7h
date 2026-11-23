-- System Parameter moved from the Freight Forwarding module to Portal Master: a role keeps what it could do there.
INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT role_id, 'pm.systemParameter', actions FROM auth.role_grant WHERE menu = 'ff.parameter'
ON CONFLICT (role_id, menu) DO NOTHING;
DELETE FROM auth.role_grant WHERE menu = 'ff.parameter';
