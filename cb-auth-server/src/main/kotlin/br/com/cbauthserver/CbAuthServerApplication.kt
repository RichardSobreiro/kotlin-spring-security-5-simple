package br.com.cbauthserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class CbAuthServerApplication()

fun main(args: Array<String>) {
	runApplication<CbAuthServerApplication>(*args)
}
