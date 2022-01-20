package br.com.cbauthserver

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.jdbc.core.JdbcTemplate
import javax.swing.tree.RowMapper

@SpringBootApplication
class CbAuthServerApplication(@Autowired val jdbcTemplate: JdbcTemplate) : CommandLineRunner {
	override fun run(vararg args: String?) {

		//Create table ("IF NOT EXISTS" syntax may not be compatible with some databases):
		jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS oauth2_authorization\n" +
				"(\n" +
				"    id                            varchar(100) NOT NULL,\n" +
				"    registered_client_id          varchar(100) NOT NULL,\n" +
				"    principal_name                varchar(200) NOT NULL,\n" +
				"    authorization_grant_type      varchar(100) NOT NULL,\n" +
				"    attributes                    varchar(4000) DEFAULT NULL,\n" +
				"    state                         varchar(500)  DEFAULT NULL,\n" +
				"    authorization_code_value      blob          DEFAULT NULL,\n" +
				"    authorization_code_issued_at  timestamp     DEFAULT NULL,\n" +
				"    authorization_code_expires_at timestamp     DEFAULT NULL,\n" +
				"    authorization_code_metadata   varchar(2000) DEFAULT NULL,\n" +
				"    access_token_value            blob          DEFAULT NULL,\n" +
				"    access_token_issued_at        timestamp     DEFAULT NULL,\n" +
				"    access_token_expires_at       timestamp     DEFAULT NULL,\n" +
				"    access_token_metadata         varchar(2000) DEFAULT NULL,\n" +
				"    access_token_type             varchar(100)  DEFAULT NULL,\n" +
				"    access_token_scopes           varchar(1000) DEFAULT NULL,\n" +
				"    oidc_id_token_value           blob          DEFAULT NULL,\n" +
				"    oidc_id_token_issued_at       timestamp     DEFAULT NULL,\n" +
				"    oidc_id_token_expires_at      timestamp     DEFAULT NULL,\n" +
				"    oidc_id_token_metadata        varchar(2000) DEFAULT NULL,\n" +
				"    refresh_token_value           blob          DEFAULT NULL,\n" +
				"    refresh_token_issued_at       timestamp     DEFAULT NULL,\n" +
				"    refresh_token_expires_at      timestamp     DEFAULT NULL,\n" +
				"    refresh_token_metadata        varchar(2000) DEFAULT NULL,\n" +
				"    PRIMARY KEY (id)\n" +
				");")
		jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS oauth2_registered_client\n" +
				"(\n" +
				"    id                            varchar(100)                            NOT NULL,\n" +
				"    client_id                     varchar(100)                            NOT NULL,\n" +
				"    client_id_issued_at           timestamp     DEFAULT CURRENT_TIMESTAMP NOT NULL,\n" +
				"    client_secret                 varchar(200)  DEFAULT NULL,\n" +
				"    client_secret_expires_at      timestamp     DEFAULT NULL,\n" +
				"    client_name                   varchar(200)                            NOT NULL,\n" +
				"    client_authentication_methods varchar(1000)                           NOT NULL,\n" +
				"    authorization_grant_types     varchar(1000)                           NOT NULL,\n" +
				"    redirect_uris                 varchar(1000) DEFAULT NULL,\n" +
				"    scopes                        varchar(1000)                           NOT NULL,\n" +
				"    client_settings               varchar(2000)                           NOT NULL,\n" +
				"    token_settings                varchar(2000)                           NOT NULL,\n" +
				"    PRIMARY KEY (id)\n" +
				");")
		jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS oauth2_authorization_consent\n" +
				"(\n" +
				"    registered_client_id varchar(100)  NOT NULL,\n" +
				"    principal_name       varchar(200)  NOT NULL,\n" +
				"    authorities          varchar(1000) NOT NULL,\n" +
				"    PRIMARY KEY (registered_client_id, principal_name)\n" +
				");")
		jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS users(\n" +
				"\tusername varchar_ignorecase(50) not null primary key,\n" +
				"\tpassword varchar_ignorecase(50) not null,\n" +
				"\tenabled boolean not null\n" +
				");")

		//Insert some records:
		//jdbcTemplate.execute("INSERT INTO favorite_beers(id, name,abv) VALUES(1, 'Lagunitas IPA', 6.2)")
		//jdbcTemplate.execute("INSERT INTO favorite_beers(id, name,abv) VALUES(2, 'Jai Alai', 7.5)")
	}
}

fun main(args: Array<String>) {
	runApplication<CbAuthServerApplication>(*args)
}
