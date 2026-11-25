-- Meeting Room module (Booking Ruang mr.booking, Persetujuan Booking mr.approval) and its Portal Master masters (Gedung &
-- Kantor pm.building, Ruang Rapat pm.meetingRoom, Fasilitas Ruang pm.roomAmenity).
-- A role keeps on the new masters what it can do on Pelabuhan & Lokasi (another location master). The built-in roles
-- book rooms (their own bookings); Publisher also approves. Other roles get nothing: an administrator grants them in
-- Peran & Hak Akses. Admin needs no rows (it holds the whole catalog).
INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT g.role_id, m.menu, g.actions FROM auth.role_grant g CROSS JOIN (VALUES ('pm.building'), ('pm.meetingRoom'), ('pm.roomAmenity')) AS m(menu)
WHERE g.menu = 'pm.port'
ON CONFLICT (role_id, menu) DO NOTHING;

INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT r.id, 'mr.booking', ARRAY['read', 'own', 'create', 'update', 'delete'] FROM auth.role r
WHERE r.is_system AND r.code IN ('analyst', 'publisher', 'viewer') AND NOT r.is_deleted
ON CONFLICT (role_id, menu) DO NOTHING;

INSERT INTO auth.role_grant (role_id, menu, actions)
SELECT r.id, 'mr.approval', ARRAY['read', 'approve', 'reject'] FROM auth.role r
WHERE r.is_system AND r.code = 'publisher' AND NOT r.is_deleted
ON CONFLICT (role_id, menu) DO NOTHING;
