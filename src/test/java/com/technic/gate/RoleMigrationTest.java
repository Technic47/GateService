package com.technic.gate;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Миграция V3 на данных, как они лежат на VPS после 0.2.0: роли-строки в user_service_role становятся ролями
 * своих сервисов, выдачи — ссылками на них. Ничего не теряется.
 */
@Testcontainers
class RoleMigrationTest {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    @Test
    void oldRoleStringsBecomeServiceRoles() throws Exception {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .target("2").load().migrate();
        try (Connection c = connection(); Statement st = c.createStatement()) {
            st.execute("insert into users (id, username, password_hash, role, created_at) values "
                    + "(1, 'pavel', 'x', 'ADMIN', now()), (2, 'anna', 'x', 'USER', now())");
            st.execute("insert into services (id, name, display_name, host, port) values "
                    + "(10, 'bikeservice', 'Bike', '127.0.0.1', 8081), (11, 'fashionmark', 'Fashion', '127.0.0.1', 8080)");
            st.execute("insert into user_service_access (user_id, service_id) values (1, 10), (2, 10), (1, 11)");
            st.execute("insert into user_service_role (user_id, service_id, role) values "
                    + "(1, 10, 'admin'), (2, 10, 'editor'), (1, 11, 'admin')");
        }

        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();

        assertThat(rows("select r.code || '@' || s.name from roles r join services s on s.id = r.service_id "
                + "order by 1"))
                .containsExactly("admin@bikeservice", "admin@fashionmark", "editor@bikeservice");
        assertThat(rows("select u.username || ':' || s.name || ':' || r.code from user_service_role x "
                + "join users u on u.id = x.user_id join services s on s.id = x.service_id "
                + "join roles r on r.id = x.role_id order by 1"))
                .containsExactly("anna:bikeservice:editor", "pavel:bikeservice:admin", "pavel:fashionmark:admin");
        assertThat(rows("select version::text from role_catalog_version")).containsExactly("1");
        // several roles per grant are possible now
        try (Connection c = connection(); Statement st = c.createStatement()) {
            st.execute("insert into user_service_role (user_id, service_id, role_id) "
                    + "select 2, 10, id from roles where code = 'admin' and service_id = 10");
        }
        assertThat(rows("select count(*)::text from user_service_role where user_id = 2")).containsExactly("2");
    }

    private static Connection connection() throws Exception {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static List<String> rows(String sql) throws Exception {
        List<String> out = new ArrayList<>();
        try (Connection c = connection(); Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        }
        return out;
    }
}
