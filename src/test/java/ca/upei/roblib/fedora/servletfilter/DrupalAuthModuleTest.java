package ca.upei.roblib.fedora.servletfilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import junit.framework.TestCase;

public class DrupalAuthModuleTest extends TestCase {
	protected DrupalAuthModuleMock mockInstance;
	
	public void setUp() throws Exception {
		super.setUp();
		
	    mockInstance = new DrupalAuthModuleMock(this.getClass().getResourceAsStream("/filter-drupal.xml"));
	    mockInstance.initialize(new Subject(), new MockHandler(), new HashMap(), new HashMap());
	}
	
	public void testFindUserUserOneHasAdministratorRole() {
		mockInstance.findUser("alpha", "first");
		assertTrue("User \"1\" gets the \"administrator\" role", mockInstance.attributeValues.contains("administrator"));
	}
	
	public void testFindUserAnonymous() {
		mockInstance.findUser("anonymous", "anonymous");
		assertTrue("Anonymous gets the anonymous role", mockInstance.attributeValues.contains(DrupalAuthModule.ANONYMOUSROLE));
	}

	public void testFindUserAuthenticatedUser() {
		Map<String,String> users = new HashMap<String, String>();
		users.put("alpha", "first");
		users.put("bravo", "second");
		users.put("charlie", "third");
		
		for (String key: users.keySet()) {
			mockInstance.findUser(key, users.get(key));
			assertTrue("Has the \"authenticated user\" role", mockInstance.attributeValues.contains("authenticated user"));
			assertFalse("Doesn't have the \"third role\"", mockInstance.attributeValues.contains("third role"));
		}
	}
	
	public void testFindUserConfiguredRoles() {
		mockInstance.findUser("alpha", "first");
		assertTrue("Alpha has proper roles", (
				mockInstance.attributeValues.contains("first role") && 
				mockInstance.attributeValues.contains("second role")));
		
		mockInstance.findUser("bravo", "second role");
		assertTrue("Bravo has proper role", mockInstance.attributeValues.contains("second role"));
	}
	
	private class MockHandler implements CallbackHandler {
		public void handle(Callback[] callbacks) throws IOException,
				UnsupportedCallbackException {
			// No-op
		}
	}
}
