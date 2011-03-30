package routines.system.esb;

public interface MessageHandler<T> {

	public ExchangeContext<T> invoke(T request); // throws Exception;

}
