package br.com.cbauthserver.authserverconfig

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.jdbc.DataSourceBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import javax.sql.DataSource


@Configuration
class WebAppConfig {
    @Bean(name = arrayOf("appDataSource"))
    @Primary
    @ConfigurationProperties(prefix = "spring.datasource")
    fun dataSource(): DataSource {
        val dataSource: DriverManagerDataSource = DriverManagerDataSource()
        dataSource.setDriverClassName("org.h2.Driver")
        dataSource.setUrl("jdbc:h2:mem:test")
        /*dataSource.setUsername(DataSourceDemo.USERNAME)
        dataSource.setPassword(DataSourceDemo.PASSWORD)*/
        return dataSource
    }

    @Bean(name = arrayOf("JdbcTemplate"))
    fun applicationDataConnection(): JdbcTemplate {
        var dataSource = dataSource()
        return JdbcTemplate(dataSource)
    }
}