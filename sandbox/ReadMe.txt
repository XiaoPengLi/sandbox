Run "RUN.BAT" to do all the things below:

1,Switch work directory and install three jars manually into local maven repository:

mvn install:install-file -DgroupId=org.talend.camel -DartifactId=UnitDemo -Dversion=1.0.0 -Dfile=UnitDemo_0.1.jar -Dpackaging=jar -DgeneratePom=true

mvn install:install-file -DgroupId=org.talend.camel -DartifactId=systemRoutines -Dversion=1.0.0 -Dfile=systemRoutines.jar -Dpackaging=jar -DgeneratePom=true

mvn install:install-file -DgroupId=org.talend.camel -DartifactId=userRoutines -Dversion=1.0.0 -Dfile=userRoutines.jar -Dpackaging=jar -DgeneratePom=true

2,Change directory to "project", create a eclipse project using "mvn eclipse:eclipse"

3,Compile project using "mvn compile"

4,Run unit test under CMD "mvn test -Dtest=FirstTest"

Also the project could be imported into eclipse, and run the FirstTest.java as JUnit test.