/**
 * 
 */
package com.talend.demo.camel_test_demo;

import java.util.Map;

import org.apache.camel.CamelContext;
import org.apache.camel.EndpointInject;
import org.apache.camel.Produce;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.test.junit4.CamelTestSupport;
import org.junit.Test;

import demo.ftptest_0_1.FTPTest;


/**
 * @author LiXP
 * 
 */
public class FirstTest extends CamelTestSupport {

	private FTPTest demo;

	private RouteBuilder route;

	@EndpointInject(uri = "mock:result")
	protected MockEndpoint resultEndpoint;

	@Produce(uri = "direct:start")
	protected ProducerTemplate template;
	
	@Test
	public void testSendMatchingMessage() throws Exception {
		
		
		String expectedBody = "<matched/>";

		resultEndpoint.expectedBodiesReceived(expectedBody);

		template.sendBodyAndHeader(expectedBody, "foo", "bar");

		resultEndpoint.assertIsSatisfied();
	}

	@Test
	public void testSendNotMatchingMessage() throws Exception {
		resultEndpoint.expectedMessageCount(1);

		template.sendBodyAndHeader("<notMatched/>", "foo",
				"notMatchedHeaderValue");

		resultEndpoint.assertIsSatisfied();
	}
	

	@Override
	protected CamelContext createCamelContext() throws Exception {
		demo = new FTPTest();
		Map<String, String> uriProperties = demo.getUriMap();
		uriProperties.put("cFtp_1", "direct:start");
		uriProperties.put("cFile_1", "mock:result");
		demo.loadCustomUriMap(uriProperties);
		route = demo.Route(false);
		context = route.getContext();
		return context;
	}

	@Override
	protected RouteBuilder createRouteBuilder() throws Exception {
		return route;
	}
}
