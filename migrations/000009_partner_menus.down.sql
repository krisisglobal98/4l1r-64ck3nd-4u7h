-- Mitra Bisnis grants go back to Customer and Vendor.
INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT role_id, m, actions FROM auth.role_grant, unnest(ARRAY['pm.customer', 'pm.vendor']) AS m WHERE menu = 'pm.businessPartner'
ON CONFLICT (role_id, menu) DO NOTHING;
DELETE FROM auth.role_grant WHERE menu = 'pm.businessPartner';
