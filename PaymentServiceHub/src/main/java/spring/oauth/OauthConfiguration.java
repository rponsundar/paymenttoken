package spring.oauth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.rowset.SqlRowSet;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.bank.psh.beans.TokenInfoResponseBean;
import com.bank.psh.beans.URNRequestBean;
import com.bank.psh.data.model.PaymentToken;
import com.bank.psh.service.utils.PshUtil;

@EnableAutoConfiguration
@RestController
@ComponentScan (basePackages = {"spring"})
@SpringBootApplication
public class OauthConfiguration extends SpringBootServletInitializer {

	public OauthConfiguration() {
		
	}

	@RequestMapping(value = "/psh/token", method = RequestMethod.POST)
	public @ResponseBody TokenInfoResponseBean getToken(
			HttpServletRequest request, HttpServletResponse response,
			@Valid @RequestBody URNRequestBean urnRequest) {
		PaymentToken pmTkn = getToken(urnRequest.getUrn());
		String crypto = PshUtil.generateCryptogram(urnRequest.getTransactionDetails(), pmTkn);
		TokenInfoResponseBean token = new TokenInfoResponseBean();
		token.setToken(pmTkn.getToken());
        token.setCryto(crypto);
		return token;
	}

	@Override
	protected SpringApplicationBuilder configure(
	        SpringApplicationBuilder application) {
	    return application.sources(OauthConfiguration.class);
	}



	@Configuration
	@EnableResourceServer
	protected static class ResourceServer extends
			ResourceServerConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.requestMatchers().antMatchers("/psh/token", "/oauth/authorize").and()
					.formLogin().and()
					.authorizeRequests().anyRequest()
					.access("#oauth2.hasScope('read')");
			// @formatter:on
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources)
				throws Exception {
			resources.resourceId("PaymentServiceHub");
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends
			AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;
		
		@Autowired
		private DataSource dataSource;
		
		@Autowired
		private ClientDetailsService clientDetailsService;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints)
				throws Exception {
			endpoints.authenticationManager(authenticationManager);
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients)
				throws Exception {
			// @formatter:off
			
			clients.jdbc(dataSource);
			/*clients.inMemory()
					.withClient("restapp")
					.authorizedGrantTypes("password", "authorization_code",
							"refresh_token", "implicit")
					.authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
					.scopes("read", "write", "trust")
					.resourceIds("PaymentServiceHub")
					.redirectUris("http://localhost:8081/Vendor.html")
					.accessTokenValiditySeconds(10)
					.autoApprove(true).and()
					
					.withClient("my-client-with-registered-redirect")
					.authorizedGrantTypes("authorization_code")
					.authorities("ROLE_CLIENT").scopes("read", "trust")
					.resourceIds("PaymentServiceHub")
					.redirectUris("http://localhost:8081/Vendor.html").and()
					
					.withClient("my-client-with-secret")
					.authorizedGrantTypes("client_credentials", "password")
					.authorities("ROLE_CLIENT").scopes("read")
					.resourceIds("PaymentServiceHub").secret("secret");*/
			// @formatter:on
		}

	}

	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Configuration
	protected static class AuthenticationSecurity extends
			GlobalAuthenticationConfigurerAdapter {

		@Override
		public void init(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth.inMemoryAuthentication().withUser("user").password("password")
					.roles("ADMIN", "USER");
			// @formatter:on
		}
	}

	private JdbcTemplate jdbcTemplate;

	@Autowired
	public OauthConfiguration(DataSource dataSource) {
		this.jdbcTemplate = new JdbcTemplate(dataSource);
	}

	public PaymentToken getToken(String urn) {
		String query = "SELECT TOKEN.TOKEN TOKEN, TOKEN.EXP_DATE EXP_DATE FROM CUST_URN_TOKEN URN, CUST_PYMT_TOKEN TOKEN WHERE URN.URN = ? AND URN.TOKEN_ID = TOKEN.ID";
		PaymentToken paymentToken = null;
		// JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

		Object[] args = new Object[] { urn };

		SqlRowSet srs = jdbcTemplate.queryForRowSet(query, args);

		if (srs != null) {
			paymentToken = new PaymentToken();
			while (srs.next()) {
				paymentToken.setToken(srs.getString("TOKEN"));
				// paymentToken.setExpDate(srs.getString("EXP_DATE"));
			}
		}

		return paymentToken;
	}
}