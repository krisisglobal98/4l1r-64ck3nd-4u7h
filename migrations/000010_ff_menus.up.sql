-- Freight Forwarding menus follow its pages (Operation, Pricing, Marketing, Invoice, Job Sheet, …). Bill of Lading
-- (ff.bl) and Pelacakan Kargo (ff.tracking) are part of Operation now, and Job Sheet is read-only: a role keeps
-- what it could do on a job, on ff.operation, and reads/exports the Job Sheet.
INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT role_id, 'ff.operation',
       ARRAY(SELECT a FROM unnest(ARRAY['read', 'create', 'update', 'delete', 'own', 'submit', 'export', 'upload']) WITH ORDINALITY AS o(a, n)
             WHERE a = ANY (all_actions) ORDER BY n)
FROM (SELECT role_id, array_agg(x) AS all_actions FROM auth.role_grant, unnest(actions) AS x
      WHERE menu IN ('ff.bl', 'ff.tracking', 'ff.jobsheet') GROUP BY role_id) g
WHERE 'read' = ANY (all_actions)
ON CONFLICT (role_id, menu) DO NOTHING;
UPDATE auth.role_grant SET actions = ARRAY(SELECT a FROM unnest(ARRAY['read', 'export']) AS a WHERE a = ANY (actions)) WHERE menu = 'ff.jobsheet';
DELETE FROM auth.role_grant WHERE menu IN ('ff.bl', 'ff.tracking') OR cardinality(actions) = 0;
