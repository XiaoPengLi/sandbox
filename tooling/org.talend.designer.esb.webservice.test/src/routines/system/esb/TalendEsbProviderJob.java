// ============================================================================
//
// %GENERATED_LICENSE%
//
// ============================================================================
package routines.system.esb;

import routines.system.TalendJob;

public interface TalendEsbProviderJob extends TalendJob {

	org.dom4j.Document invoke(org.dom4j.Document request) throws TEsbException;

	org.dom4j.Document invokeAndDie(org.dom4j.Document request) throws TEsbException;

	void stopExposingProviderJob();
}
