// ============================================================================
//
// %GENERATED_LICENSE%
//
// ============================================================================
package routines.system.esb;

public interface TalendEsbProviderJob extends routines.system.TalendJob {

	MessageHandler<org.dom4j.Document> getInvoker();

	void stopExposingProviderJob();
}
