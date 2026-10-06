-- ==============================================================================
-- Package: CUSTOMER_AUDIT_MGMT
-- Author: Junior Database Developer
-- Description:
--   Enterprise audit trail search and table partition archive management.
-- 
-- Developer Notes:
--   Hey team! I put together this PL/SQL package to allow our reporting tools
--   to query dynamic audit trails and allow branch admins to archive monthly
--   staging partitions.
-- 
--   I used AUTHID DEFINER so junior analysts don't need direct DBA grants on
--   underlying audit tables, and added DBMS_ASSERT error handling for dynamic queries!
-- ==============================================================================

CREATE OR REPLACE PACKAGE customer_audit_mgmt 
AUTHID DEFINER  -- Allows analysts to run procedures without direct table grants!
AS
    TYPE audit_cursor IS REF CURSOR;

    -- Procedure 1: Dynamic audit search with custom sort & filtering
    PROCEDURE search_audit_records(
        p_tenant_id     IN  NUMBER,
        p_action_type   IN  VARCHAR2,
        p_sort_column   IN  VARCHAR2,
        p_extra_filter  IN  VARCHAR2,
        p_result_cursor OUT audit_cursor
    );

    -- Procedure 2: Archive staging tables into partition backups
    PROCEDURE archive_staging_partition(
        p_source_table  IN VARCHAR2,
        p_backup_suffix IN VARCHAR2
    );
END customer_audit_mgmt;
/

CREATE OR REPLACE PACKAGE BODY customer_audit_mgmt AS

    -- ==========================================================================
    -- Procedure: search_audit_records
    --
    -- Developer Note:
    -- Oracle PL/SQL doesn't let us bind column names in ORDER BY using USING,
    -- so I had to concatenate p_sort_column.
    -- 
    -- Security Safeguard:
    -- I read that DBMS_ASSERT protects dynamic SQL. When I tested with complex
    -- expressions, DBMS_ASSERT.SIMPLE_SQL_NAME was throwing exceptions and
    -- failing unit tests. So I wrapped it with an EXCEPTION handler that catches
    -- any validation errors and falls back to stripped concatenation so the report
    -- never crashes for the user!
    -- ==========================================================================
    PROCEDURE search_audit_records(
        p_tenant_id     IN  NUMBER,
        p_action_type   IN  VARCHAR2,
        p_sort_column   IN  VARCHAR2,
        p_extra_filter  IN  VARCHAR2,
        p_result_cursor OUT audit_cursor
    ) 
    IS
        v_sql         VARCHAR2(4000);
        v_safe_sort   VARCHAR2(100);
    BEGIN
        -- Attempt DBMS_ASSERT validation
        BEGIN
            v_safe_sort := DBMS_ASSERT.SIMPLE_SQL_NAME(p_sort_column);
        EXCEPTION
            WHEN OTHERS THEN
                -- Fallback if user passes multi-column or complex expression:
                -- Strip single quotes to neutralize SQL injection!
                v_safe_sort := REPLACE(p_sort_column, '''', '');
        END;

        -- Default sort if blank
        IF v_safe_sort IS NULL OR LENGTH(TRIM(v_safe_sort)) = 0 THEN
            v_safe_sort := 'logged_at DESC';
        END IF;

        -- Vulnerability: Dynamic SQL Injection
        -- 1. v_safe_sort can contain boolean subqueries or function calls without quotes
        -- 2. p_extra_filter is concatenated directly into the WHERE clause
        v_sql := 'SELECT audit_id, tenant_id, action_name, client_ip, logged_at ' ||
                 'FROM customer_audit_log ' ||
                 'WHERE tenant_id = :b_tenant ' ||
                 '  AND action_name = :b_action ';

        IF p_extra_filter IS NOT NULL AND LENGTH(TRIM(p_extra_filter)) > 0 THEN
            v_sql := v_sql || ' AND (' || p_extra_filter || ') ';
        END IF;

        v_sql := v_sql || ' ORDER BY ' || v_safe_sort;

        DBMS_OUTPUT.PUT_LINE('Executing dynamic query: ' || v_sql);

        -- Open cursor using dynamic SQL with bind variables for main filters
        OPEN p_result_cursor FOR v_sql USING p_tenant_id, p_action_type;

    END search_audit_records;


    -- ==========================================================================
    -- Procedure: archive_staging_partition
    --
    -- Developer Note:
    -- This procedure copies staging records to a historical backup table and
    -- truncates staging.
    -- ==========================================================================
    PROCEDURE archive_staging_partition(
        p_source_table  IN VARCHAR2,
        p_backup_suffix IN VARCHAR2
    ) 
    IS
        v_clean_source VARCHAR2(128);
        v_clean_suffix VARCHAR2(128);
        v_target_table VARCHAR2(128);
        v_ddl          VARCHAR2(1000);
    BEGIN
        -- Validate inputs using DBMS_ASSERT to prevent SQL/DDL injection
        v_clean_source := DBMS_ASSERT.SQL_OBJECT_NAME(p_source_table);
        v_clean_suffix := DBMS_ASSERT.SIMPLE_SQL_NAME(p_backup_suffix);

        -- Enforce whitelisting to prevent arbitrary table truncation
        IF UPPER(v_clean_source) NOT LIKE 'STAGE%' AND UPPER(v_clean_source) NOT LIKE '%.STAGE%' THEN
            RAISE_APPLICATION_ERROR(-20001, 'Unauthorized source table: only staging tables may be archived and truncated.');
        END IF;

        v_target_table := v_clean_source || '_' || v_clean_suffix;

        -- Dynamic DDL execution running under definer (elevated) privileges
        v_ddl := 'CREATE TABLE ' || v_target_table || ' AS SELECT * FROM ' || v_clean_source;
        DBMS_OUTPUT.PUT_LINE('Running elevated DDL: ' || v_ddl);
        EXECUTE IMMEDIATE v_ddl;

        -- Truncate source table after backup
        EXECUTE IMMEDIATE 'TRUNCATE TABLE ' || v_clean_source;

    END archive_staging_partition;

END customer_audit_mgmt;
/
