package ca.upei.roblib.fedora.servletfilter;

import java.io.InputStream;

public class DrupalAuthModuleMock extends DrupalAuthModule {
	protected InputStream stream;
	public DrupalAuthModuleMock(InputStream stream) {
		this.stream = stream;
	}
	
	protected InputStream getConfig() {
		return this.stream;
	}
}
