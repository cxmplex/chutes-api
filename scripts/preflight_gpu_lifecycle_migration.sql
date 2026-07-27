-- Read-only rollout preflight for 20260725120000_gpu_lifecycle_durability.sql.
-- Run against the predecessor schema. Any `blocking_live` row must be repaired
-- deliberately before dbmate is allowed to apply the migration.
WITH reservation_candidates AS (
    SELECT node.uuid,
           ARRAY_AGG(reservation.reservation_id::TEXT ORDER BY reservation.reservation_id)
               FILTER (WHERE reservation.reservation_id IS NOT NULL) AS reservation_ids,
           COUNT(reservation.reservation_id) AS reservation_count
      FROM nodes AS node
      LEFT JOIN gpu_launch_reservations AS reservation
        ON reservation.allocation_group_id = node.gpu_allocation_group_id
       AND reservation.allocation_group_generation = node.gpu_allocation_group_generation
       AND reservation.server_id = node.server_id
       AND reservation.gpu_uuids ? node.uuid
     WHERE node.gpu_allocation_group_id IS NOT NULL
     GROUP BY node.uuid
), classified AS (
    SELECT node.uuid,
           node.server_id,
           node.gpu_allocation_group_id,
           node.gpu_allocation_group_generation,
           node.gpu_retired_at,
           COALESCE(candidate.reservation_ids, ARRAY[]::TEXT[]) AS reservation_ids,
           CASE
               WHEN node.gpu_retired_at IS NOT NULL
                    AND candidate.reservation_count = 1
                    AND allocation_group.generation = node.gpu_allocation_group_generation
                   THEN 'repairable_retired'
               WHEN node.gpu_retired_at IS NOT NULL
                   THEN 'retired_projection_cleared'
               WHEN server.gpu_launch_reservation_id IS NOT NULL
                    AND server.gpu_allocation_group_id = node.gpu_allocation_group_id
                    AND server.gpu_allocation_group_generation = node.gpu_allocation_group_generation
                    AND server.gpu_process_incarnation IS NOT NULL
                    AND allocation_group.generation = node.gpu_allocation_group_generation
                    AND current_reservation.reservation_id = server.gpu_launch_reservation_id
                    AND current_reservation.process_incarnation = server.gpu_process_incarnation
                    AND current_reservation.gpu_uuids ? node.uuid
                   THEN 'repairable_live'
               ELSE 'blocking_live'
           END AS migration_status
      FROM nodes AS node
      LEFT JOIN reservation_candidates AS candidate ON candidate.uuid = node.uuid
      LEFT JOIN servers AS server ON server.server_id = node.server_id
      LEFT JOIN gpu_allocation_groups AS allocation_group
        ON allocation_group.allocation_group_id = node.gpu_allocation_group_id
      LEFT JOIN gpu_launch_reservations AS current_reservation
        ON current_reservation.reservation_id = server.gpu_launch_reservation_id
     WHERE node.gpu_allocation_group_id IS NOT NULL
)
SELECT uuid,
       server_id,
       gpu_allocation_group_id,
       gpu_allocation_group_generation,
       gpu_retired_at,
       reservation_ids,
       migration_status
  FROM classified
 ORDER BY (migration_status = 'blocking_live') DESC,
          migration_status,
          uuid;
