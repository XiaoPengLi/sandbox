/**
 * 
 */
package com.talend.demo.camel_test_demo;

import org.apache.camel.CamelContext;
import org.apache.camel.EndpointInject;
import org.apache.camel.Produce;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.component.properties.PropertiesComponent;
import org.apache.camel.test.junit4.CamelTestSupport;
import org.junit.Test;

import demo.unitdemo_0_1.UnitDemo;

/**
 * @author LiXP
 * 
 */
public class FirstTest extends CamelTestSupport {

	private UnitDemo demo;

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
		resultEndpoint.expectedMessageCount(0);

		template.sendBodyAndHeader("<notMatched/>", "foo",
				"notMatchedHeaderValue");

		resultEndpoint.assertIsSatisfied();
	}
	

	@Override
	protected CamelContext createCamelContext() throws Exception {
		demo = new UnitDemo();
		route = demo.Route(false);
		//Reset the properties
		CamelContext context = route.getContext();
		PropertiesComponent component = (PropertiesComponent) context.getComponent("properties");
		component.setLocation("UnitDemo_0.1.properties");
		return context;
	}

	@Override
	protected RouteBuilder createRouteBuilder() throws Exception {
		return route;
	}
}
