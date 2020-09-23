package com.bdoclient.apihelper.config;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;



@Configuration
@EnableSwagger2
public class SpringFoxConfig {                                    
    @Bean
    public Docket api() { 
        return new Docket(DocumentationType.SWAGGER_2) 
        		.select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any())
                .build().consumes(DEFAULT_PRODUCES_AND_CONSUMES).produces(DEFAULT_PRODUCES_AND_CONSUMES)
                .apiInfo(apiInfo());
    }
    
    private ApiInfo apiInfo() {
		return new ApiInfoBuilder().title("BDO GSP/ASP API Utility")
				.description("BDO GSP/ASP API reference for developers")
				.termsOfServiceUrl("http://einvoice.bdo.in")
				.contact(contactInfo()).license("@BDO India LLP")
				.version("1.0")
				.build();
	}
    private static final Set<String> DEFAULT_PRODUCES_AND_CONSUMES = 
    	      new HashSet<String>(Arrays.asList("application/json"));
    private Contact contactInfo() {
    	return new Contact("Mitul Visaria ","http://einvoice.bdo.in","MitulVisaria@bdo.in");
    }
}
