package com.tad.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("test")
@SpringBootTest(properties = {
	"spring.datasource.url=jdbc:h2:mem:tad_gateway_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH",
	"spring.datasource.username=sa",
	"spring.datasource.password=",
	"spring.datasource.driver-class-name=org.h2.Driver",
	"spring.jpa.hibernate.ddl-auto=create-drop",
	"spring.jpa.properties.hibernate.hbm2ddl.create_namespaces=true",
	"app.jwt.issuer=tad-test",
	"app.jwt.access-minutes=30",
	"app.jwt.refresh-minutes=10080",
	"app.jwt.secret-base64=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
})
class TadGatewayApplicationTests {

	@Test
	void contextLoads() {
	}
}
