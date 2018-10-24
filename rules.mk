.PHONY: buildJava
.PHONY: cleanJava
.PHONY: releaseJava
.PHONY: testJava

distclean:: cleanJava
clean:: cleanJava

dist:: releaseJava
release_classes:: releaseJava

check:: testJava
test_jss:: testJava

html:: javadoc

# always do a private_export
export:: private_export

CORE_VARIABLES=     \
    "JSS_OBJDIR_NAME=$(OBJDIR_NAME)" \
    "SOURCE_PREFIX=$(SOURCE_PREFIX)" \
    "SOURCE_RELEASE_PREFIX=$(SOURCE_RELEASE_PREFIX)" \
    "SOURCE_RELEASE_CLASSES_DIR=$(SOURCE_RELEASE_CLASSES_DIR)" \

PERL_VARIABLES= \
    $(CORE_VARIABLES) \
    "XPCLASS_JAR=$(XPCLASS_JAR)"

REPRODUCIBLE_VARIABLES= \
    $(CORE_VARIABLES) \
    "XPCLASS_JAR=reproducible-$(XPCLASS_JAR)"

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

reproducible:
	bash tools/reproducible_jar.sh "$(SOURCE_PREFIX)/$(XPCLASS_JAR)" "$(SOURCE_PREFIX)/reproducible" "$(SOURCE_PREFIX)/reproducible-$(XPCLASS_JAR)"

reproducibleCheck:
	perl build_java.pl $(REPRODUCIBLE_VARIABLES) test
