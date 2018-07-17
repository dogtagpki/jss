.PHONY: buildJava
.PHONY: cleanJava
.PHONY: releaseJava
.PHONY: testJava

clean:: cleanJava
release_classes:: releaseJava

# always do a private_export
export:: private_export

PERL_VARIABLES=     \
    "JSS_OBJDIR_NAME=$(OBJDIR_NAME)" \
    "SOURCE_PREFIX=$(SOURCE_PREFIX)" \
    "SOURCE_RELEASE_PREFIX=$(SOURCE_RELEASE_PREFIX)" \
    "SOURCE_RELEASE_CLASSES_DIR=$(SOURCE_RELEASE_CLASSES_DIR)" \
    "XPCLASS_JAR=$(XPCLASS_JAR)"

buildJava:
	perl build_java.pl $(PERL_VARIABLES) build

cleanJava:
	perl build_java.pl $(PERL_VARIABLES) clean

testJava:
	perl build_java.pl $(PERL_VARIABLES) test

releaseJava:
	perl build_java.pl $(PERL_VARIABLES) release

javadoc:
	perl build_java.pl $(PERL_VARIABLES) javadoc
