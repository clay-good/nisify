"""
Snowflake collector for Nisify.

Collects security evidence from Snowflake including access history,
query history, login history, user/role configuration, and encryption status.
All queries are read-only SELECT statements against ACCOUNT_USAGE views.

Required Snowflake Permissions:
    - IMPORTED PRIVILEGES on SNOWFLAKE database
    - Or explicit SELECT on ACCOUNT_USAGE schema views:
      - SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY
      - SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
      - SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
      - SNOWFLAKE.ACCOUNT_USAGE.USERS
      - SNOWFLAKE.ACCOUNT_USAGE.ROLES
      - SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
      - SNOWFLAKE.ACCOUNT_USAGE.SECURITY_INTEGRATIONS

Authentication:
    Credentials are retrieved from the credential store with keys:
    - snowflake_account: Snowflake account identifier
    - snowflake_user: Username
    - snowflake_password: Password (for password auth)
    OR
    - snowflake_private_key: Private key content (for key-pair auth)
    - snowflake_private_key_path: Path to private key file
    - snowflake_private_key_passphrase: Passphrase for encrypted key (optional)

    Optional:
    - snowflake_warehouse: Warehouse to use for queries
    - snowflake_role: Role to assume for queries

Compute Cost Notes:
    All queries in this collector use the ACCOUNT_USAGE views which:
    - May have up to 45 minutes of latency
    - Require a running warehouse for execution
    - Consume compute credits based on warehouse size and query duration

    Default date range is 30 days. Queries are designed to be efficient
    and use appropriate filters to minimize data scanned.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from nisify.collectors.base import (
    AuthenticationError,
    BaseCollector,
    CollectionResult,
    CollectorConnectionError,
    CollectorRegistry,
    Evidence,
)

if TYPE_CHECKING:
    from nisify.config.credentials import CredentialStore
    from nisify.config.settings import Settings


@CollectorRegistry.register
class SnowflakeCollector(BaseCollector):
    """
    Snowflake evidence collector.

    Collects security-relevant evidence from Snowflake:
        - Access history (data_access_logs)
        - Query history (access_logs)
        - Login history (authentication_logs)
        - User and role configuration (user_inventory, access_policies)
        - Security integrations (identity_federation)

    Evidence Types Collected:
        - data_access_logs: Who accessed what data and when
        - access_logs: All queries executed
        - authentication_logs: Login attempts and results
        - user_inventory: All Snowflake users
        - access_policies: Roles and grants
        - identity_federation: SSO and SCIM configuration

    Compute Cost Warning:
        Queries against ACCOUNT_USAGE views consume warehouse compute credits.
        Default warehouse size and query efficiency are designed to minimize costs.

    Example:
        collector = SnowflakeCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "snowflake"
    default_rate_limit_delay = 0.5  # Snowflake queries can be expensive

    # Default data retention window in days
    DEFAULT_RETENTION_DAYS = 30

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Snowflake collector.

        Args:
            config: Settings object containing Snowflake configuration.
            credential_store: Credential store for retrieving Snowflake credentials.
        """
        super().__init__(config, credential_store)
        self._connection: Any = None
        self._snowflake_connector: Any = None

    def _get_snowflake_connector(self) -> Any:
        """
        Lazily import snowflake-connector-python.

        Returns:
            snowflake.connector module.

        Raises:
            CollectorConnectionError: If package is not installed.
        """
        if self._snowflake_connector is None:
            try:
                import snowflake.connector

                self._snowflake_connector = snowflake.connector
            except ImportError:
                raise CollectorConnectionError(
                    "snowflake-connector-python is not installed. "
                    "Install it with: pip install snowflake-connector-python",
                    platform=self.platform,
                )
        return self._snowflake_connector

    def _get_connection(self) -> Any:
        """
        Get or create a Snowflake connection.

        Returns:
            Snowflake connection object.

        Raises:
            AuthenticationError: If authentication fails.
            CollectorConnectionError: If connection fails.
        """
        if self._connection is not None:
            try:
                # Test if connection is still valid
                cursor = self._connection.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                return self._connection
            except Exception:
                # Connection is stale, reconnect
                try:
                    self._connection.close()
                except Exception:
                    pass
                self._connection = None

        snowflake = self._get_snowflake_connector()

        # Get required credentials
        account = self.get_credential("snowflake_account")
        user = self.get_credential("snowflake_user")

        # Build connection parameters
        connect_params: dict[str, Any] = {
            "account": account,
            "user": user,
        }

        # Try key-pair authentication first, then password
        try:
            private_key = self.get_credential("snowflake_private_key")
            connect_params["private_key"] = self._parse_private_key(private_key)
        except AuthenticationError:
            try:
                private_key_path = self.get_credential("snowflake_private_key_path")
                with open(private_key_path, "rb") as f:
                    private_key = f.read().decode()
                connect_params["private_key"] = self._parse_private_key(private_key)
            except AuthenticationError:
                # Fall back to password auth
                password = self.get_credential("snowflake_password")
                connect_params["password"] = password

        # Optional parameters
        try:
            warehouse = self.get_credential("snowflake_warehouse")
            connect_params["warehouse"] = warehouse
        except AuthenticationError:
            pass

        try:
            role = self.get_credential("snowflake_role")
            connect_params["role"] = role
        except AuthenticationError:
            pass

        # Connect
        try:
            self._connection = snowflake.connect(**connect_params)
            self.logger.debug(f"Connected to Snowflake account: {account}")
            return self._connection
        except snowflake.errors.DatabaseError as e:
            if "Incorrect username or password" in str(e):
                raise AuthenticationError(
                    f"Snowflake authentication failed: {e}",
                    platform=self.platform,
                )
            raise CollectorConnectionError(
                f"Failed to connect to Snowflake: {e}",
                platform=self.platform,
            )

    def _parse_private_key(self, key_content: str) -> bytes:
        """
        Parse a private key for Snowflake authentication.

        Args:
            key_content: PEM-encoded private key string.

        Returns:
            DER-encoded private key bytes.

        Raises:
            AuthenticationError: If key parsing fails.
        """
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            raise AuthenticationError(
                "cryptography package required for key-pair authentication",
                platform=self.platform,
            )

        # Check for passphrase
        passphrase_bytes: bytes | None = None
        try:
            passphrase_str = self.get_credential("snowflake_private_key_passphrase")
            passphrase_bytes = passphrase_str.encode()
        except AuthenticationError:
            pass

        try:
            private_key = serialization.load_pem_private_key(
                key_content.encode(),
                password=passphrase_bytes,
                backend=default_backend(),
            )
            return private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        except Exception as e:
            raise AuthenticationError(
                f"Failed to parse Snowflake private key: {e}",
                platform=self.platform,
            )

    def _execute_query(
        self,
        query: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a query and return results as list of dicts.

        Args:
            query: SQL query string.
            params: Query parameters.

        Returns:
            List of result rows as dictionaries.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        start_time = time.time()
        self._rate_limit()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            duration_ms = (time.time() - start_time) * 1000
            self._log_api_call("QUERY", query[:50] + "...", None, duration_ms)

            # Get column names
            columns = [desc[0].lower() for desc in cursor.description]

            # Fetch all results
            rows = cursor.fetchall()

            # Convert to list of dicts
            results = []
            for row in rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    value = row[i]
                    # Convert datetime objects to ISO strings
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    row_dict[col] = value
                results.append(row_dict)

            return results

        finally:
            cursor.close()

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Snowflake permission strings.
        """
        return [
            "IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE",
            "OR SELECT ON SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY",
            "SELECT ON SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY",
            "SELECT ON SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY",
            "SELECT ON SNOWFLAKE.ACCOUNT_USAGE.USERS",
            "SELECT ON SNOWFLAKE.ACCOUNT_USAGE.ROLES",
            "SELECT ON SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS",
            "SELECT ON SNOWFLAKE.ACCOUNT_USAGE.SECURITY_INTEGRATIONS",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Snowflake.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            results = self._execute_query("SELECT CURRENT_USER(), CURRENT_ROLE()")
            if results:
                user = results[0].get("current_user()")
                role = results[0].get("current_role()")
                self.logger.info(
                    f"Snowflake connection successful. User: {user}, Role: {role}"
                )
            return True
        except Exception as e:
            self.logger.error(f"Snowflake connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Snowflake.

        Returns:
            CollectionResult with all collected evidence.
        """
        start_time = time.time()
        evidence_items: list[Evidence] = []
        errors: list[str] = []
        collected_types: list[str] = []
        failed_types: list[str] = []

        collectors = [
            ("user_inventory", self._collect_users),
            ("access_policies", self._collect_roles_and_grants),
            ("authentication_logs", self._collect_login_history),
            ("access_logs", self._collect_query_history),
            ("data_access_logs", self._collect_access_history),
            ("identity_federation", self._collect_security_integrations),
        ]

        for evidence_type, collector_func in collectors:
            try:
                self.logger.info(f"Collecting {evidence_type}...")
                items = collector_func()
                evidence_items.extend(items)
                collected_types.append(evidence_type)
                self.logger.info(f"Collected {len(items)} items for {evidence_type}")
            except AuthenticationError:
                raise
            except Exception as e:
                self.logger.error(f"Failed to collect {evidence_type}: {e}")
                errors.append(f"{evidence_type}: {str(e)}")
                failed_types.append(evidence_type)

        duration = time.time() - start_time

        # Close connection when done
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None

        if len(errors) == 0:
            success = True
            partial = False
        elif len(collected_types) > 0:
            success = True
            partial = True
        else:
            success = False
            partial = False

        return CollectionResult(
            platform=self.platform,
            timestamp=datetime.now(UTC),
            success=success,
            evidence_items=evidence_items,
            errors=errors,
            duration_seconds=duration,
            partial=partial,
        )

    def _collect_users(self) -> list[Evidence]:
        """
        Collect user inventory from ACCOUNT_USAGE.USERS.

        Returns:
            List of Evidence items with user inventory.
        """
        query = """
        SELECT
            name,
            created_on,
            login_name,
            display_name,
            email,
            disabled,
            default_role,
            default_warehouse,
            last_success_login,
            has_password,
            must_change_password,
            has_rsa_public_key,
            ext_authn_duo,
            ext_authn_uid
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE deleted_on IS NULL
        ORDER BY name
        """

        users = self._execute_query(query)

        # Calculate summary
        total_users = len(users)
        disabled_count = sum(1 for u in users if u.get("disabled"))
        mfa_count = sum(1 for u in users if u.get("ext_authn_duo"))
        key_auth_count = sum(1 for u in users if u.get("has_rsa_public_key"))

        return [
            self.normalize_evidence(
                {
                    "users": users,
                    "total_users": total_users,
                    "active_users": total_users - disabled_count,
                    "disabled_users": disabled_count,
                    "mfa_enabled_count": mfa_count,
                    "key_pair_auth_count": key_auth_count,
                },
                "user_inventory",
                {"source": "snowflake_account_usage_users"},
            )
        ]

    def _collect_roles_and_grants(self) -> list[Evidence]:
        """
        Collect roles and user grants.

        Returns:
            List of Evidence items with access policies.
        """
        # Get roles
        roles_query = """
        SELECT
            name,
            created_on,
            is_default,
            is_current,
            is_inherited,
            assigned_to_users,
            granted_to_roles,
            granted_roles,
            owner,
            comment
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
        WHERE deleted_on IS NULL
        ORDER BY name
        """
        roles = self._execute_query(roles_query)

        # Get grants to users
        grants_query = """
        SELECT
            role,
            grantee_name,
            granted_by,
            created_on
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE deleted_on IS NULL
        ORDER BY grantee_name, role
        """
        grants = self._execute_query(grants_query)

        # Calculate summary
        total_roles = len(roles)
        total_grants = len(grants)

        # Count users per role
        role_user_counts: dict[str, int] = {}
        for grant in grants:
            role = grant.get("role", "unknown")
            role_user_counts[role] = role_user_counts.get(role, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "roles": roles,
                    "user_grants": grants,
                    "total_roles": total_roles,
                    "total_grants": total_grants,
                    "role_user_counts": role_user_counts,
                },
                "access_policies",
                {"source": "snowflake_account_usage_roles"},
            )
        ]

    def _collect_login_history(self) -> list[Evidence]:
        """
        Collect login history from ACCOUNT_USAGE.LOGIN_HISTORY.

        Returns:
            List of Evidence items with authentication logs.
        """
        retention_days = self.DEFAULT_RETENTION_DAYS
        start_date = datetime.now(UTC) - timedelta(days=retention_days)

        query = """
        SELECT
            event_timestamp,
            event_type,
            user_name,
            client_ip,
            reported_client_type,
            reported_client_version,
            first_authentication_factor,
            second_authentication_factor,
            is_success,
            error_code,
            error_message
        FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
        WHERE event_timestamp >= %s
        ORDER BY event_timestamp DESC
        LIMIT 10000
        """

        logins = self._execute_query(query, params=(start_date.strftime("%Y-%m-%d"),))

        # Calculate summary
        total_logins = len(logins)
        successful = sum(1 for login in logins if login.get("is_success"))
        failed = total_logins - successful

        # Count by user
        user_login_counts: dict[str, int] = {}
        for login in logins:
            user = login.get("user_name", "unknown")
            user_login_counts[user] = user_login_counts.get(user, 0) + 1

        # Count failures by error
        error_counts: dict[str, int] = {}
        for login in logins:
            if not login.get("is_success"):
                error = login.get("error_message", "unknown")
                error_counts[error] = error_counts.get(error, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "logins": logins,
                    "total_logins": total_logins,
                    "successful_count": successful,
                    "failed_count": failed,
                    "success_rate_percent": (
                        (successful / total_logins * 100) if total_logins > 0 else 0
                    ),
                    "user_login_counts": user_login_counts,
                    "error_counts": error_counts,
                    "date_range_days": retention_days,
                },
                "authentication_logs",
                {"source": "snowflake_account_usage_login_history"},
            )
        ]

    def _collect_query_history(self) -> list[Evidence]:
        """
        Collect query history from ACCOUNT_USAGE.QUERY_HISTORY.

        Note: This query samples the query history to avoid excessive
        compute costs. Full query text is truncated.

        Returns:
            List of Evidence items with access logs.
        """
        retention_days = self.DEFAULT_RETENTION_DAYS
        start_date = datetime.now(UTC) - timedelta(days=retention_days)

        query = """
        SELECT
            query_id,
            query_type,
            start_time,
            end_time,
            total_elapsed_time,
            user_name,
            role_name,
            database_name,
            schema_name,
            warehouse_name,
            warehouse_size,
            execution_status,
            error_code,
            error_message,
            rows_produced,
            bytes_scanned,
            LEFT(query_text, 200) as query_text_sample
        FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
        WHERE start_time >= %s
        ORDER BY start_time DESC
        LIMIT 5000
        """

        queries = self._execute_query(query, params=(start_date.strftime("%Y-%m-%d"),))

        # Calculate summary
        total_queries = len(queries)
        successful = sum(1 for q in queries if q.get("execution_status") == "SUCCESS")

        # Count by query type
        query_type_counts: dict[str, int] = {}
        for q in queries:
            qt = q.get("query_type", "unknown")
            query_type_counts[qt] = query_type_counts.get(qt, 0) + 1

        # Count by user
        user_query_counts: dict[str, int] = {}
        for q in queries:
            user = q.get("user_name", "unknown")
            user_query_counts[user] = user_query_counts.get(user, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "queries": queries,
                    "total_queries": total_queries,
                    "successful_count": successful,
                    "failed_count": total_queries - successful,
                    "query_type_counts": query_type_counts,
                    "user_query_counts": user_query_counts,
                    "date_range_days": retention_days,
                    "note": "Query text truncated to 200 characters to reduce data size",
                },
                "access_logs",
                {"source": "snowflake_account_usage_query_history"},
            )
        ]

    def _collect_access_history(self) -> list[Evidence]:
        """
        Collect data access history from ACCOUNT_USAGE.ACCESS_HISTORY.

        This shows who accessed what tables/views and when.

        Returns:
            List of Evidence items with data access logs.
        """
        retention_days = self.DEFAULT_RETENTION_DAYS
        start_date = datetime.now(UTC) - timedelta(days=retention_days)

        query = """
        SELECT
            query_id,
            query_start_time,
            user_name,
            role_name,
            direct_objects_accessed,
            base_objects_accessed,
            objects_modified
        FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY
        WHERE query_start_time >= %s
        ORDER BY query_start_time DESC
        LIMIT 5000
        """

        try:
            access_records = self._execute_query(query, params=(start_date.strftime("%Y-%m-%d"),))
        except Exception as e:
            # ACCESS_HISTORY may not be available in all accounts
            self.logger.warning(f"ACCESS_HISTORY query failed: {e}")
            return [
                self.normalize_evidence(
                    {
                        "access_records": [],
                        "total_records": 0,
                        "note": "ACCESS_HISTORY not available or no data",
                    },
                    "data_access_logs",
                    {"source": "snowflake_account_usage_access_history"},
                )
            ]

        # Calculate summary
        total_records = len(access_records)

        # Count by user
        user_access_counts: dict[str, int] = {}
        for r in access_records:
            user = r.get("user_name", "unknown")
            user_access_counts[user] = user_access_counts.get(user, 0) + 1

        # Count unique objects accessed
        objects_accessed: set[str] = set()
        for r in access_records:
            direct = r.get("direct_objects_accessed", [])
            if isinstance(direct, list):
                for obj in direct:
                    if isinstance(obj, dict):
                        objects_accessed.add(obj.get("objectName", ""))

        return [
            self.normalize_evidence(
                {
                    "access_records": access_records[:1000],  # Limit stored records
                    "total_records": total_records,
                    "unique_objects_accessed": len(objects_accessed),
                    "user_access_counts": user_access_counts,
                    "date_range_days": retention_days,
                },
                "data_access_logs",
                {"source": "snowflake_account_usage_access_history"},
            )
        ]

    def _collect_security_integrations(self) -> list[Evidence]:
        """
        Collect security integrations (SSO, SCIM).

        Returns:
            List of Evidence items with identity federation config.
        """
        query = """
        SELECT
            name,
            type,
            category,
            enabled,
            created_on,
            comment
        FROM SNOWFLAKE.ACCOUNT_USAGE.SECURITY_INTEGRATIONS
        WHERE deleted_on IS NULL
        ORDER BY name
        """

        try:
            integrations = self._execute_query(query)
        except Exception as e:
            self.logger.warning(f"SECURITY_INTEGRATIONS query failed: {e}")
            integrations = []

        # Calculate summary
        total_integrations = len(integrations)
        enabled_count = sum(1 for i in integrations if i.get("enabled"))

        # Group by type
        type_counts: dict[str, int] = {}
        for i in integrations:
            t = i.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        # Check for SSO and SCIM
        has_sso = any(
            i.get("type") in ["SAML2", "OAUTH"]
            and i.get("enabled")
            for i in integrations
        )
        has_scim = any(
            i.get("type") == "SCIM" and i.get("enabled")
            for i in integrations
        )

        return [
            self.normalize_evidence(
                {
                    "integrations": integrations,
                    "total_integrations": total_integrations,
                    "enabled_count": enabled_count,
                    "type_counts": type_counts,
                    "sso_enabled": has_sso,
                    "scim_enabled": has_scim,
                },
                "identity_federation",
                {"source": "snowflake_account_usage_security_integrations"},
            )
        ]
