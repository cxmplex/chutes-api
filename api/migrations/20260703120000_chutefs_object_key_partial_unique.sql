-- migrate:up

-- This branch migration can run against either the deployed soft-delete catalog or an ORM
-- create_all catalog that already contains the later immutable-generation model. Transition only
-- the exact legacy authority, accept the exact post-migration or final authority, and reject mixed
-- or same-name/wrong-shape WIP catalogs.
DO $$
DECLARE
    has_deleted BOOLEAN;
    has_lifecycle_state BOOLEAN;
    key_columns SMALLINT[];
    matching_constraints TEXT[];
    matching_unique_indexes INTEGER;
    legacy_index_oid OID;
    auto_index_oid OID;
    current_index_oid OID;
    legacy_constraint pg_constraint%ROWTYPE;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_attribute
         WHERE attrelid = 'storage_objects'::regclass
           AND attname = 'deleted' AND attnum > 0 AND NOT attisdropped
    ) INTO has_deleted;
    SELECT EXISTS (
        SELECT 1 FROM pg_attribute
         WHERE attrelid = 'storage_objects'::regclass
           AND attname = 'lifecycle_state' AND attnum > 0 AND NOT attisdropped
    ) INTO has_lifecycle_state;
    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'storage_objects'::regclass
            AND attname = 'volume_id' AND attnum > 0 AND NOT attisdropped),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'storage_objects'::regclass
            AND attname = 'object_key' AND attnum > 0 AND NOT attisdropped)
    ]::SMALLINT[] INTO key_columns;
    IF array_position(key_columns, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'storage_objects lacks exact object-key columns';
    END IF;

    SELECT array_agg(constraint_row.conname::TEXT ORDER BY constraint_row.conname)
      INTO matching_constraints
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'storage_objects'::regclass
       AND constraint_row.contype = 'u'
       AND constraint_row.conkey = key_columns;
    SELECT COUNT(*)
      INTO matching_unique_indexes
      FROM pg_index AS index_definition
     WHERE index_definition.indrelid = 'storage_objects'::regclass
       AND index_definition.indisunique
       AND index_definition.indnkeyatts = 2
       AND index_definition.indnatts = 2
       AND index_definition.indkey::TEXT = array_to_string(key_columns, ' ')
       AND index_definition.indexprs IS NULL;
    SELECT relation.oid INTO legacy_index_oid
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'uq_storage_object_key';
    SELECT relation.oid INTO auto_index_oid
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'storage_objects_volume_id_object_key_key';
    SELECT relation.oid INTO current_index_oid
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'uq_storage_object_current';

    IF has_deleted AND NOT has_lifecycle_state THEN
        IF NOT EXISTS (
            SELECT 1
              FROM pg_attribute AS attribute
              JOIN pg_attrdef AS attribute_default
                ON attribute_default.adrelid = attribute.attrelid
               AND attribute_default.adnum = attribute.attnum
             WHERE attribute.attrelid = 'storage_objects'::regclass
               AND attribute.attname = 'deleted'
               AND format_type(attribute.atttypid, attribute.atttypmod) = 'boolean'
               AND attribute.attnotnull
               AND pg_get_expr(attribute_default.adbin, attribute_default.adrelid) = 'false'
        ) THEN
            RAISE EXCEPTION 'legacy storage_objects.deleted has invalid definition';
        END IF;
        IF current_index_oid IS NOT NULL THEN
            RAISE EXCEPTION
                'mixed storage object-key authority contains legacy deleted and final current index';
        END IF;

        IF COALESCE(cardinality(matching_constraints), 0) = 1 THEN
            SELECT * INTO STRICT legacy_constraint
              FROM pg_constraint AS constraint_row
             WHERE constraint_row.conrelid = 'storage_objects'::regclass
               AND constraint_row.conname = matching_constraints[1];
            IF legacy_constraint.conname NOT IN (
                    'storage_objects_volume_id_object_key_key',
                    'uq_storage_object_key'
               )
               OR legacy_constraint.condeferrable
               OR legacy_constraint.condeferred
               OR NOT legacy_constraint.convalidated
               OR lower(
                    regexp_replace(
                        pg_get_constraintdef(legacy_constraint.oid, TRUE),
                        '[[:space:]]+', '', 'g'
                    )
               ) <> 'unique(volume_id,object_key)'
               OR matching_unique_indexes <> 1
               OR NOT EXISTS (
                    SELECT 1
                      FROM pg_index AS index_definition
                      JOIN pg_class AS index_relation
                        ON index_relation.oid = index_definition.indexrelid
                      JOIN pg_am AS access_method
                        ON access_method.oid = index_relation.relam
                     WHERE index_definition.indexrelid = legacy_constraint.conindid
                       AND index_definition.indrelid = 'storage_objects'::regclass
                       AND index_relation.relkind = 'i'
                       AND access_method.amname = 'btree'
                       AND index_definition.indisunique
                       AND NOT index_definition.indisprimary
                       AND NOT index_definition.indisexclusion
                       AND index_definition.indimmediate
                       AND index_definition.indisvalid
                       AND index_definition.indisready
                       AND index_definition.indislive
                       AND index_definition.indnkeyatts = 2
                       AND index_definition.indnatts = 2
                       AND index_definition.indkey::TEXT =
                           array_to_string(key_columns, ' ')
                       AND index_definition.indoption::TEXT = '0 0'
                       AND index_definition.indexprs IS NULL
                       AND index_definition.indpred IS NULL
               ) THEN
                RAISE EXCEPTION
                    'legacy storage object-key unique constraint has invalid shape';
            END IF;
            EXECUTE format(
                'ALTER TABLE storage_objects DROP CONSTRAINT %I',
                legacy_constraint.conname
            );
            SELECT relation.oid INTO legacy_index_oid
              FROM pg_class AS relation
              JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = current_schema()
               AND relation.relname = 'uq_storage_object_key';
            IF legacy_index_oid IS NOT NULL THEN
                RAISE EXCEPTION
                    'unexpected uq_storage_object_key relation remains after legacy transition';
            END IF;
            EXECUTE
                'CREATE UNIQUE INDEX uq_storage_object_key '
                'ON storage_objects (volume_id, object_key) '
                'WHERE deleted IS false';
        ELSIF COALESCE(cardinality(matching_constraints), 0) <> 0 THEN
            RAISE EXCEPTION
                'legacy storage object-key authority has duplicate constraints: %',
                matching_constraints;
        END IF;

        SELECT COUNT(*)
          INTO matching_unique_indexes
          FROM pg_index AS index_definition
         WHERE index_definition.indrelid = 'storage_objects'::regclass
           AND index_definition.indisunique
           AND index_definition.indnkeyatts = 2
           AND index_definition.indnatts = 2
           AND index_definition.indkey::TEXT = array_to_string(key_columns, ' ')
           AND index_definition.indexprs IS NULL;
        SELECT relation.oid INTO legacy_index_oid
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = current_schema()
           AND relation.relname = 'uq_storage_object_key';
        IF COALESCE(cardinality(matching_constraints), 0) = 0
           AND (matching_unique_indexes <> 1 OR legacy_index_oid IS NULL) THEN
            RAISE EXCEPTION
                'expected exact pre- or post-migration legacy storage object-key authority';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM pg_index AS index_definition
              JOIN pg_class AS index_relation
                ON index_relation.oid = index_definition.indexrelid
              JOIN pg_am AS access_method
                ON access_method.oid = index_relation.relam
             WHERE index_definition.indexrelid = legacy_index_oid
               AND index_definition.indrelid = 'storage_objects'::regclass
               AND index_relation.relkind = 'i'
               AND access_method.amname = 'btree'
               AND index_definition.indisunique
               AND NOT index_definition.indisprimary
               AND NOT index_definition.indisexclusion
               AND index_definition.indimmediate
               AND index_definition.indisvalid
               AND index_definition.indisready
               AND index_definition.indislive
               AND index_definition.indnkeyatts = 2
               AND index_definition.indnatts = 2
               AND index_definition.indkey::TEXT = array_to_string(key_columns, ' ')
               AND index_definition.indoption::TEXT = '0 0'
               AND index_definition.indexprs IS NULL
               AND lower(
                    translate(
                        regexp_replace(
                            pg_get_expr(
                                index_definition.indpred,
                                index_definition.indrelid,
                                TRUE
                            ),
                            '[[:space:]]+', '', 'g'
                        ),
                        '()', ''
                    )
               ) = 'deletedisfalse'
        ) THEN
            RAISE EXCEPTION 'uq_storage_object_key has invalid legacy partial-index shape';
        END IF;
    ELSIF NOT has_deleted AND has_lifecycle_state THEN
        IF NOT EXISTS (
            SELECT 1
              FROM pg_attribute AS attribute
              JOIN pg_attrdef AS attribute_default
                ON attribute_default.adrelid = attribute.attrelid
               AND attribute_default.adnum = attribute.attnum
             WHERE attribute.attrelid = 'storage_objects'::regclass
               AND attribute.attname = 'lifecycle_state'
               AND format_type(attribute.atttypid, attribute.atttypmod) =
                   'character varying'
               AND attribute.attnotnull
               AND pg_get_expr(attribute_default.adbin, attribute_default.adrelid) =
                   '''pending''::character varying'
        ) THEN
            RAISE EXCEPTION 'final storage_objects.lifecycle_state has invalid definition';
        END IF;
        IF COALESCE(cardinality(matching_constraints), 0) <> 0
           OR matching_unique_indexes <> 1
           OR legacy_index_oid IS NOT NULL
           OR auto_index_oid IS NOT NULL
           OR current_index_oid IS NULL THEN
            RAISE EXCEPTION
                'final storage object-key authority is missing, duplicated, or mixed';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM pg_index AS index_definition
              JOIN pg_class AS index_relation
                ON index_relation.oid = index_definition.indexrelid
              JOIN pg_am AS access_method
                ON access_method.oid = index_relation.relam
             WHERE index_definition.indexrelid = current_index_oid
               AND index_definition.indrelid = 'storage_objects'::regclass
               AND index_relation.relkind = 'i'
               AND access_method.amname = 'btree'
               AND index_definition.indisunique
               AND NOT index_definition.indisprimary
               AND NOT index_definition.indisexclusion
               AND index_definition.indimmediate
               AND index_definition.indisvalid
               AND index_definition.indisready
               AND index_definition.indislive
               AND index_definition.indnkeyatts = 2
               AND index_definition.indnatts = 2
               AND index_definition.indkey::TEXT = array_to_string(key_columns, ' ')
               AND index_definition.indoption::TEXT = '0 0'
               AND index_definition.indexprs IS NULL
               AND lower(
                    translate(
                        regexp_replace(
                            pg_get_expr(
                                index_definition.indpred,
                                index_definition.indrelid,
                                TRUE
                            ),
                            '[[:space:]]+', '', 'g'
                        ),
                        '()', ''
                    )
               ) = 'lifecycle_state::text=''committed''::text'
        ) THEN
            RAISE EXCEPTION 'uq_storage_object_current has invalid final partial-index shape';
        END IF;
    ELSE
        RAISE EXCEPTION
            'storage object-key migration requires exact legacy or final columns; deleted=%, lifecycle_state=%',
            has_deleted,
            has_lifecycle_state;
    END IF;
END
$$;

-- migrate:down

DO $$
DECLARE
    has_deleted BOOLEAN;
    has_lifecycle_state BOOLEAN;
    key_columns SMALLINT[];
    legacy_index_oid OID;
    current_index_oid OID;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_attribute
         WHERE attrelid = 'storage_objects'::regclass
           AND attname = 'deleted' AND attnum > 0 AND NOT attisdropped
    ) INTO has_deleted;
    SELECT EXISTS (
        SELECT 1 FROM pg_attribute
         WHERE attrelid = 'storage_objects'::regclass
           AND attname = 'lifecycle_state' AND attnum > 0 AND NOT attisdropped
    ) INTO has_lifecycle_state;
    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'storage_objects'::regclass AND attname = 'volume_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'storage_objects'::regclass AND attname = 'object_key')
    ]::SMALLINT[] INTO key_columns;
    SELECT relation.oid INTO legacy_index_oid
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'uq_storage_object_key';
    SELECT relation.oid INTO current_index_oid
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'uq_storage_object_current';

    IF has_deleted AND NOT has_lifecycle_state THEN
        IF legacy_index_oid IS NULL OR NOT EXISTS (
            SELECT 1 FROM pg_index AS index_definition
             WHERE index_definition.indexrelid = legacy_index_oid
               AND index_definition.indrelid = 'storage_objects'::regclass
               AND index_definition.indisunique
               AND index_definition.indnkeyatts = 2
               AND index_definition.indnatts = 2
               AND index_definition.indkey::TEXT = array_to_string(key_columns, ' ')
               AND index_definition.indexprs IS NULL
               AND lower(
                    translate(
                        regexp_replace(
                            pg_get_expr(
                                index_definition.indpred,
                                index_definition.indrelid,
                                TRUE
                            ),
                            '[[:space:]]+', '', 'g'
                        ),
                        '()', ''
                    )
               ) = 'deletedisfalse'
        ) THEN
            RAISE EXCEPTION
                'cannot reverse non-canonical legacy storage object-key authority';
        END IF;
        EXECUTE 'DROP INDEX uq_storage_object_key';
        EXECUTE
            'ALTER TABLE storage_objects '
            'ADD CONSTRAINT uq_storage_object_key UNIQUE (volume_id, object_key)';
    ELSIF NOT has_deleted AND has_lifecycle_state THEN
        IF legacy_index_oid IS NOT NULL OR current_index_oid IS NULL THEN
            RAISE EXCEPTION
                'cannot no-op reverse mixed final storage object-key authority';
        END IF;
        -- The up migration was a no-op against the later final catalog, so down is also a no-op.
        NULL;
    ELSE
        RAISE EXCEPTION
            'cannot reverse mixed storage object-key columns; deleted=%, lifecycle_state=%',
            has_deleted,
            has_lifecycle_state;
    END IF;
END
$$;
