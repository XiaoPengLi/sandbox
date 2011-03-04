package org.apache.cxf.ws.security.sts.provider.operation;

import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenType;

public interface ValidateOperation {

	RequestSecurityTokenResponseType validate(
			RequestSecurityTokenType request);

}
