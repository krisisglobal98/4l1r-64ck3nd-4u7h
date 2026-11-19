-- Portal Master replaced the Freight Forwarding masters Customer (pm.customer) and Vendor (pm.vendor) with one global
-- master, Mitra Bisnis (pm.businessPartner): a role keeps what it could do in either, now on Mitra Bisnis.
INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT role_id, 'pm.businessPartner',
       ARRAY(SELECT a FROM unnest(ARRAY['read', 'own', 'create', 'update', 'delete', 'submit', 'approve', 'reject', 'unapprove', 'export', 'upload']) WITH ORDINALITY AS o(a, n)
             WHERE a = ANY (array_agg_all) ORDER BY n)
FROM (SELECT role_id, array_agg(x) AS array_agg_all
      FROM auth.role_grant, unnest(actions) AS x WHERE menu IN ('pm.customer', 'pm.vendor') GROUP BY role_id) g
ON CONFLICT (role_id, menu) DO NOTHING;
DELETE FROM auth.role_grant WHERE menu IN ('pm.customer', 'pm.vendor');
