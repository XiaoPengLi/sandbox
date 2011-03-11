/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cxf.ws.security.sts.provider;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.soap.Detail;
import javax.xml.soap.DetailEntry;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.Provider;
import javax.xml.ws.Service;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceProvider;
import javax.xml.ws.soap.SOAPFaultException;
import org.w3c.dom.Node;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.ws.security.sts.provider.operation.CancelOperation;
import org.apache.cxf.ws.security.sts.provider.operation.IssueOperation;
import org.apache.cxf.ws.security.sts.provider.operation.KeyExchangeTokenOperation;
import org.apache.cxf.ws.security.sts.provider.operation.RenewOperation;
import org.apache.cxf.ws.security.sts.provider.operation.RequestCollectionOperation;
import org.apache.cxf.ws.security.sts.provider.operation.ValidateOperation;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseCollectionType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenType;

@WebServiceProvider(serviceName = "SecurityTokenServiceProvider", 
        portName = "SecurityTokenServiceSOAP", 
        targetNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/wsdl", 
        wsdlLocation = "WEB-INF/classes/model/ws-trust-1.4-service.wsdl")
@ServiceMode(value = Service.Mode.PAYLOAD)
public class SecurityTokenServiceProvider implements Provider<Source> {

    private static final Log LOG = LogFactory
            .getLog(SecurityTokenServiceProvider.class.getName());

    private static final String WSTRUST_13_NAMESPACE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static final String WSTRUST_REQUESTTYPE_ELEMENTNAME = "RequestType";
    private static final String WSTRUST_REQUESTTYPE_ISSUE = WSTRUST_13_NAMESPACE
            + "/Issue";
    private static final String WSTRUST_REQUESTTYPE_CANCEL = WSTRUST_13_NAMESPACE
            + "/Cancel";
    private static final String WSTRUST_REQUESTTYPE_RENEW = WSTRUST_13_NAMESPACE
            + "/Renew";
    private static final String WSTRUST_REQUESTTYPE_VALIDATE = WSTRUST_13_NAMESPACE
            + "/Validate";
    private static final String WSTRUST_REQUESTTYPE_REQUESTCOLLECTION = WSTRUST_13_NAMESPACE
            + "/RequestCollection";
    private static final String WSTRUST_REQUESTTYPE_KEYEXCHANGETOKEN = WSTRUST_13_NAMESPACE
            + "/KeyExchangeToken";

    private static final String JAXB_CONTEXT_PATH = "org.oasis_open.docs.ws_sx.ws_trust._200512";
    private JAXBContext jaxbContext;
    private MessageFactory factory;
    private SOAPFactory soapFactory;
    private CancelOperation cancelOperation;
    private IssueOperation issueOperation;
    private KeyExchangeTokenOperation keyExchangeTokenOperation;
    private RenewOperation renewOperation;
    private RequestCollectionOperation requestCollectionOperation;
    private ValidateOperation validateOperation;
    private Map<String, Object> operationMap = new HashMap<String, Object>();

    public SecurityTokenServiceProvider() throws Exception {
        jaxbContext = JAXBContext.newInstance(JAXB_CONTEXT_PATH);
        factory = MessageFactory.newInstance();
        soapFactory = SOAPFactory.newInstance();
    }
    
    public void setCancelOperation(CancelOperation cancelOperation) {
        this.cancelOperation = cancelOperation;
        operationMap.put(WSTRUST_REQUESTTYPE_CANCEL, cancelOperation);
    }

    public void setIssueOperation(IssueOperation issueOperation) {
        this.issueOperation = issueOperation;
        operationMap.put(WSTRUST_REQUESTTYPE_ISSUE, issueOperation);
    }

    public void setKeyExchangeTokenOperation(
            KeyExchangeTokenOperation keyExchangeTokenOperation) {
        this.keyExchangeTokenOperation = keyExchangeTokenOperation;
        operationMap.put(WSTRUST_REQUESTTYPE_KEYEXCHANGETOKEN,
                keyExchangeTokenOperation);
    }

    public void setRenewOperation(RenewOperation renewOperation) {
        this.renewOperation = renewOperation;
        operationMap.put(WSTRUST_REQUESTTYPE_RENEW, renewOperation);
    }

    public void setRequestCollectionOperation(
            RequestCollectionOperation requestCollectionOperation) {
        this.requestCollectionOperation = requestCollectionOperation;
        operationMap.put(WSTRUST_REQUESTTYPE_REQUESTCOLLECTION,
                requestCollectionOperation);
    }

    public void setValidateOperation(ValidateOperation validateOperation) {
        this.validateOperation = validateOperation;
        operationMap.put(WSTRUST_REQUESTTYPE_VALIDATE, validateOperation);
    }

    

    public Source invoke(Source request) {
        DOMSource response = new DOMSource();
        try {
            RequestSecurityTokenType rst = convertToJAXBObject(request);
            Object operationImpl = null;
            List<?> objectList = rst.getAny();
            for (int i = 0; i < objectList.size(); i++) {
                Object obj = objectList.get(i);
                if (obj instanceof JAXBElement) {
                    QName qname = ((JAXBElement<?>) obj).getName();
                    if (qname.equals(new QName(WSTRUST_13_NAMESPACE,
                            WSTRUST_REQUESTTYPE_ELEMENTNAME))) {
                        operationImpl = operationMap.get(((JAXBElement<?>) obj)
                                .getValue().toString());
                        break;
                    }

                }
            }

            if (operationImpl == null) {
                throw new Exception(
                        "Implementation for this operation not found.");
            }
            Method[] methods = operationImpl.getClass().getMethods();
            for (int x = 0; x < methods.length; x++) {
                Class<?>[] paramClass = methods[x].getParameterTypes();
                if (paramClass.length == 1
                        && paramClass[0].equals(rst.getClass())) {
                    RequestSecurityTokenResponseCollectionType tokenResponse = 
                        (RequestSecurityTokenResponseCollectionType) methods[x]
                            .invoke(operationImpl, rst);
                    Node responseNode = convertJAXBToNode(tokenResponse);
                    response.setNode(responseNode);
                    break;
                }
            }

            if (response.getNode() == null) {
                throw new Exception("Error in implementation class.");
            }

        } catch (Exception e) {
            LOG.error(e);
            try {
                SOAPFault fault = soapFactory.createFault();
                if (e.getMessage() == null) {
                    fault.setFaultString(e.getCause().getMessage());
                } else {
                    fault.setFaultString(e.getMessage());
                }
                Detail detail = fault.addDetail();
                detail = fault.getDetail();
                QName qName = new QName(WSTRUST_13_NAMESPACE, "Fault", "ns");
                DetailEntry de = detail.addDetailEntry(qName);
                qName = new QName(WSTRUST_13_NAMESPACE, "ErrorCode", "ns");
                SOAPElement errorElement = de.addChildElement(qName);
                StackTraceElement[] ste = e.getStackTrace();
                errorElement.setTextContent(ste[0].toString());
                throw new SOAPFaultException(fault);
            } catch (SOAPException e1) {
                LOG.error(e1);
            }

        }

        return response;
    }

    private RequestSecurityTokenType convertToJAXBObject(Source source) throws Exception {
        RequestSecurityTokenType request = null;
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        JAXBElement<?> jaxbElement = (JAXBElement<?>) unmarshaller
                .unmarshal(source);
        request = (RequestSecurityTokenType) jaxbElement.getValue();
        return request;
    }

    private Node convertJAXBToNode(
            RequestSecurityTokenResponseCollectionType response) throws Exception {
        SOAPMessage soapResponse = null;
        Marshaller marshaller = jaxbContext.createMarshaller();
        soapResponse = factory.createMessage();

        marshaller.marshal(
                new JAXBElement<RequestSecurityTokenResponseCollectionType>(
                        new QName("uri", "local"),
                        RequestSecurityTokenResponseCollectionType.class,
                        response), soapResponse.getSOAPPart());
        Node msgNode = soapResponse.getSOAPPart().getFirstChild()
                .getFirstChild();
        
        return msgNode;
    }

    public CancelOperation getCancelOperation() {
        return cancelOperation;
    }

    public IssueOperation getIssueOperation() {
        return issueOperation;
    }

    public KeyExchangeTokenOperation getKeyExchangeTokenOperation() {
        return keyExchangeTokenOperation;
    }

    public RenewOperation getRenewOperation() {
        return renewOperation;
    }

    public RequestCollectionOperation getRequestCollectionOperation() {
        return requestCollectionOperation;
    }

    public ValidateOperation getValidateOperation() {
        return validateOperation;
    }

}
