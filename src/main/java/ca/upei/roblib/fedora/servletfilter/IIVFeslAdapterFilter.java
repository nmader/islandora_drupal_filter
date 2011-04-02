package ca.upei.roblib.fedora.servletfilter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class IIVFeslAdapterFilter implements Filter {

	private static final String PARAMETER_NAME_UID = "uid";

	static class Wrapper extends HttpServletRequestWrapper {

		public Wrapper(HttpServletRequest request) {
			super(request);
		}

		@Override
		public String getHeader(String name) {
			if ("authorization".equalsIgnoreCase(name)) {
				return "Basic " + getParameter(PARAMETER_NAME_UID);
			}

			return super.getHeader(name);
		}
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;

		String auth = request.getParameter(PARAMETER_NAME_UID);

		if (auth != null && !"".equals(auth)) {
			httpRequest = new Wrapper(httpRequest);
		}

		chain.doFilter(httpRequest, response);
	}

	@Override
	public void init(FilterConfig config) throws ServletException {
	}

	@Override
	public void destroy() {
	}
}
