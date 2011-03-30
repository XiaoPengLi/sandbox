// ============================================================================
//
// %GENERATED_LICENSE%
//
// ============================================================================
package routines.system.esb;

public class TEsbException extends Exception {

	private final org.dom4j.Document detail;

	public TEsbException() {
		this("tEsbException");
	}

	public TEsbException(String message) {
		super(message);
		detail = null;
	}

	public TEsbException(String message, org.dom4j.Document detail) {
		super(message);
		this.detail = detail;
	}
}
