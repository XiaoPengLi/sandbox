package test.testproviderjobd_0_1;

import org.dom4j.Document;

import routines.system.esb.ExchangeContext;
import routines.system.esb.MessageHandler;
import routines.system.esb.TalendEsbProviderJob;

import routines.system.TalendJob;

public class ESBMockLauncher {


	public static void main(String[] args) throws Exception {

		TalendEsbProviderJob testProviderJobD = new TestProviderJobD();

		// inform about ESB environment
		((TestProviderJobD) testProviderJobD).runInEsb = true; // or via context params

		// start job in separate thread
		startJob(testProviderJobD, args);
		Thread.sleep(100); // delay for job initialization

		// get invoker
		MessageHandler<Document> invoker = testProviderJobD.getInvoker();


		org.dom4j.Document request = org.dom4j.DocumentHelper.parseText("<input>world</input>");
		processCall(invoker, request);

		org.dom4j.Document request2 = org.dom4j.DocumentHelper.parseText("<input></input>");
		processCall(invoker, request2);

		org.dom4j.Document request3 = org.dom4j.DocumentHelper.parseText("<input>xxx</input>");
		processCall(invoker, request3);

		// stop job
		testProviderJobD.stopExposingProviderJob();
		invoker.invoke(null);

	}

	private static void processCall(MessageHandler<Document> invoker, Document request)
			throws Exception {
		System.out.println("---");
		System.out.println("@@@ request passed to job: " + request.asXML());
		ExchangeContext<Document> exchangeContext = invoker.invoke(request);
		try {
			if (!exchangeContext.isFault()) {
				Document response = exchangeContext.getResponse();
				if (null == response) {
					System.out.println("@@@ empty response produced by job");
				} else {
					System.out.println("@@@ response is produced by job: " + response.asXML());
				}
			} else {
				String faultString = exchangeContext.getFaultMessage();
				if (exchangeContext.isBusinessFault()) {
					Document faultDetail = exchangeContext.getBusinessFaultDetails();
					System.out.println("@@@ business fault produced by job: " + faultString + "\n"
							+ ((null == faultDetail) ? "[no details]" : faultDetail.asXML()));
				} else {
					System.out.println("@@@ job technical error occurs: " + faultString);
				}
			}
			System.out.println();
		} finally {
			exchangeContext.completeQueuedProcessing();
		}
	}

	private static void startJob(final TalendJob talendJob, final String[] args) {

		Thread jobRunner = new Thread() {

			public void run() {
				talendJob.runJobInTOS(args);
			}
		};

		jobRunner.start();
	}
}
