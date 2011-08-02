0. Create the project structure by running the following command in ${basedir}:

mvn archetype:generate -DarchetypeCatalog=local

1. Copy your wsdl in ${basedir}/common/src/main/resources/model/service-wsdls and delete the dummy service.wsdl from the same directory.

2. In ${basedir}/pom.xml, update the following properties according to your wsdl:

	cxf.wsdl.name <- the filename of the wsdl file you copied in step 1
	cxf.service.namespace <- /wsdl:definitions@targetNamespace (relevant for client and service)
	cxf.service.name <- /wsdl:portType@name (relevant for client and service)
	cxf.endpoint.name <- /wsdl:service@name (relevant for client and service)
	cxf.endpoint.address <- the actual endpoint where the client can connect to the service  (relevant for client)
	cxf.service.interface <- the name of the interface that JAXB creates from the wsdl	(relevant for client)
		Found in ${basedir}/common/target/generated-sources/cxf after running 'mvn compile' in the common module
	cxf.client.bean <- the id by which you want to refer to your client bean (ok to leave set to default)
	cxf.service.class.implementation <- The class that you need to provide as service implementation  (relevant for service)

3. In ${basedir}/common, generate the boilerplate and JAXB classes by running

	mvn clean compile
	
	Update the information in the parent pom (see step 2) if needed.
	
	If working from Eclipse, you should add the classes that were generated from the WSDL to the build path.
	To do that, refresh the common project in the Package Explorer, right click on the folder 
	common/target/generated-sources/cxf and select "Build Path -> Use as Source Folder"

4. If the preceeding step is successfull, deploy the common jar to your local maven repo by running

	mvn install	
