package routines.system.esb;

public interface ExchangeContext<T> {

	/**
	 * This operation have to be called on the Web Service
	 * thread to send response if required
	 *
	 * @throws InterruptedException
	 */
	void completeQueuedProcessing() throws InterruptedException;

//	T getInputMessage();

	boolean isFault();

	boolean isBusinessFault();

	T getResponse();

	String getFaultMessage();

	T getBusinessFaultDetails();

	Throwable getFault();
}
