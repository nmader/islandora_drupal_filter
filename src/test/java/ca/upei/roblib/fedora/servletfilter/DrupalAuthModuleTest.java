package ca.upei.roblib.fedora.servletfilter;

import junit.framework.TestCase;

public class DrupalAuthModuleTest extends TestCase {
	protected DrupalAuthModuleMock mockInstance;
	
	public void setUp() throws Exception {
		super.setUp();
		
	    mockInstance = new DrupalAuthModuleMock(this.getClass().getResourceAsStream("filter-drupal.xml"));	
	}

	public void testFindUser() {
		fail("Not yet implemented");
	}
}
