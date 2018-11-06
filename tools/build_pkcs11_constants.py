#!/usr/bin/env python3

"""
Copyright (C) 2018 Red Hat
See licenses in base of jss repository:
https://github.com/dogtagpki/jss

Utility to automatically build PKCS11Constants.java from NSS's pkcs11t.h
and pkcs11n.h headers. See documentation under docs/pkcs11_constants.md
for more information.
"""

import os
import subprocess
import tempfile

import argparse
import textwrap


def parse_c_value(c_value):
    """
    Evaluates a given c numeric value and converts it to a hexadecimal
    value. Returns the resulting value.
    """

    # Without introducing external dependencies, this is the best way
    # to parse the value of the constant. Since this step is used in a
    # explicitly-user-controlled environment (the user passed the paths
    # to the header files we parse here), this is no worse than the
    # user calling eval() themselves. Further, this is only run manually,
    # and not as part of every build, so again this should be considered
    # safe within our use cases and threat model. Thus, disable pylint
    # the warnings about eval for this function.

    # pylint: disable=eval-used
    value = eval(c_value.replace('UL', '').replace('L', ''))
    value = hex(value)
    value = value[2:].upper()
    value = "0x" + "0" * (8 - len(value)) + value

    return value


class ConstantDefinition(object):
    """
    Wrapper class to accumlate information about a constant's definition. This
    tracks all the information necessary to define a constant and represent
    its context in the ecosystem.
    """

    # Since this is largely a data-storage class, we're bound to have too many
    # attributes because we're tracking metadata about the constants and their
    # values. Disable pylint warnings related to this.

    # pylint: disable=too-many-instance-attributes,too-many-arguments

    PREFIXES = ['CKA_', 'CKC_', 'CKD_', 'CKF_', 'CKG_', 'CKH_', 'CKK_', 'CKM_',
                'CKN_', 'CKO_', 'CKP_', 'CKR_', 'CKS_', 'CKT_', 'CKU_', 'CKZ_',
                'NSSCK_', 'SFTK_']

    def __init__(self, header_file="pkcs11t.h", line_number=1, line="",
                 name="DEFAULT", value=1):
        self.header_file = header_file
        self.line_number = line_number
        self.line = line.replace('/*', '/ *').replace('*/', '* /')
        self.name = name
        self.value = value
        self.checked = False
        self.resolved = False
        self.stdout = ""
        self.stderr = ""
        self.resolved_history = []
        self.resolved_value = ""

    def resolve_value(self, other_constants):
        """
        Given a list of other constants (also of type ConstantDefinition),
        get their values and resolve this constant's value based off of
        the other constants and their values. In particular, if this
        constant's value includes as a substring a key from other_constants,
        replace the occurrence with the value from the other constant. Note
        that other_constants must be a pre-ordered list in reverse
        alphabetical order.

        E.g., for the map { "a": "b | c", "b": "3", "c": "4"}, then "a"
        will eventually resolve to "3 | 4".

        The resolved value and the resolution chain are attached to instance
        variables:
            self.resolved_value
            self.resolved_history

        And self.resolved is set to True.
        """

        value = self.value
        value_history = []
        changed = True

        # Since we can't truly parse C in Python (or, parse C well outside of
        # a C compiler), we can't really parse the obj's value for tokens and
        # then check if the tokens match our constants and replace them.
        # So, we loop while the constant was changed.
        while changed:
            changed = False

            # One of our assertions was that other_constants was provided to
            # us in reverse alphabetical order. This means that the constant
            # "AA" is present before "A"; thus a simple loop lets us process
            # symbols in the expected order if they're present in this obj's
            # value. One example is CKT_NSS_UNTRUSTED: it has a value of
            # "CKT_NSS_MUST_VERIFY_TRUST", but CKT_NSS is another token; if
            # "CKT_NSS" is processed first, CKT_NSS_UNTRUSTED then takes
            # a value of "(0xCE534350)_MUST_VERIFY_TRUST" which isn't a valid
            # value.
            for obj in other_constants:
                if obj.name in value:
                    # We wrap the replacement in parenthesis in case it is a
                    # mathematical expression which needs to be parsed. These
                    # parenthesis disappear when we compute its value later,
                    # after we are done resolving all symbols into numeric
                    # expressions.
                    replacement = '(' + obj.value + ')'

                    # Note that if the target symbol is already resolved, we
                    # can save the steps of resolving its value again by using
                    # its resolved value here. This has the side effect of
                    # shortening our resolution history in verbose mode, but
                    # that history is still all contained in the output file.
                    if obj.resolved:
                        replacement = '(' + obj.resolved_value + ')'

                    value_history.append((value, obj.name, replacement))
                    value = value.replace(obj.name, replacement)
                    changed = True

        # Pass the processed numeric expression for value into "parse_c_value"
        # and save it as the resolved value.
        self.resolved_value = parse_c_value(value)
        self.resolved_history = value_history
        self.resolved = True

    def check_output(self, nss_args):
        """
        Checks the output of cc against the value of the constant in this
        object. This ensures that what we think the value to be is what was
        intended for the value to be. Raises an exception if the value
        differs.
        """

        # This made an intentional design choice to run each constant's check
        # separately; we could've grouped several (or all) of the constants
        # together in one check like we did the output Java class, but this has
        # the downside of making detecting which symbol is incorrect harder.

        # Small, minimal template to check if the value differs. If it does,
        # this program will exit with status 1 which we detect later. This
        # also helps to ensure that our resolved value truly is numeric.
        program_template = """
        #include "pkcs11t.h"
        #include "pkcs11n.h"

        int main() {
            if (%s != %s) {
                return 1;
            }
            return 0;
        }
        """ % (self.name, self.resolved_value)

        # Create a temporary directory; this is preserved in case of failure
        # such that the caller of this script can identify why it failed.
        temp_dir = tempfile.mkdtemp(prefix="tmp-jss-pkcs11constants-")
        path = os.path.join(temp_dir, "test.c")
        exec_path = os.path.join(temp_dir, "test.exe")

        temp_program = open(path, 'w')
        temp_program.write(program_template)
        temp_program.close()

        # Build a minimal cc call; note that nss_args is the output from
        # pkg-config such that we can correctly link this program and
        # have the correct includes for nss.
        cc_call = ["cc", "-o", exec_path, path] + nss_args
        proc = subprocess.Popen(cc_call, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        proc.wait()

        self.stdout = proc.stdout.read()
        if not isinstance(self.stdout, str):
            self.stdout = self.stdout.decode('utf8')

        self.stderr = proc.stderr.read()
        if not isinstance(self.stderr, str):
            self.stderr = self.stderr.decode('utf8')

        if self.stdout:
            print("When checking symbol '%s' (stdout):" % self.name)
            print(self.stdout)
            print("\n")

        if self.stderr:
            print("When checking symbol '%s' (stderr):" % self.name)
            print(self.stderr)
            print("\n")

        # Check whether or not the program compiled correctly; note that
        # this comes after the stdout/stderr writes, so our caller can
        # see what the error was.
        ret = proc.returncode
        if proc.returncode != 0:
            raise Exception(("Unknown error with symbol '%s': cc ret: %d " +
                             "@ %s; command: %s") % (self.name, ret, temp_dir,
                                                     ' '.join(cc_call)))

        # Since the program compiled correctly, run it to ensure the value
        # is correct.
        ret = subprocess.call(exec_path)
        if ret != 0:
            raise Exception(("Value for symbol '%s' different from expected:" +
                             " wasn't '%s' @ %s") % (self.name, self.resolved_value, temp_dir))

        # With no errors, clean up the temporary data.
        if os.path.exists(exec_path):
            os.remove(exec_path)

        if os.path.exists(path):
            os.remove(path)

        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)

        self.checked = True

    def is_included(self):
        """
        Returns true iff name begins with an allowed prefix.
        """

        for prefix in self.PREFIXES:
            if self.name.startswith(prefix):
                return True

        return False

    def get_source_content(self, verbose):
        """
        Converts a value to a Java-like value in its source context. This
        processes the value to convert it to Java and also appends
        context information when verbose information has been specified.

        Note that if verbose is specified, the prefixed comments can differ
        based on whether or not system was specified and extended checks
        were run.
        """

        # In particular, "source context" means in this case "comments"
        # and the particular java delcaration. Our constants must be of
        # type long because several of them exceed the value of a signed
        # integer and Java lacks unsigned integers. One example is
        # CKT_NSS which has value 0xCE534350.

        # We make the requirement strict here that all values are numeric
        # and resolved of all internal symbols.
        if not self.resolved:
            raise Exception("Must resolve all references before calling!")

        comment_header = "\n    /**\n"
        comment_info = "     * Content automatically generated; see NSS "
        comment_info += "documentation for more information.\n"
        comment_info += "     *\n"
        comment_info += "     * Source file: %s\n" % self.header_file

        # In verbose mode, output additional debugging information.
        if verbose:
            comment_info += "     * Line number: %s\n" % self.line_number
            comment_info += "     * Line: %s\n" % self.line
            comment_info += "     * Parsed name: %s\n" % self.name
            comment_info += "     * Parsed value: %s\n" % self.value

        # In verbose mode, save resolution history. This is useful for
        # detecting errors made during resolution.
        if self.resolved_history and verbose:
            comment_info += "     *\n"
            for step in self.resolved_history:
                comment_info += ("     * Resolution step: in [%s]\n" +
                                 "     *   replaced [%s] with [%s]\n") % step

        # In verbose mode, save the output of the system/cc check, if any.
        if self.checked and verbose:
            if self.stdout:
                comment_info += "     *\n"
                comment_info += "     * check stdout:\n"
                for line in self.stdout.split("\n"):
                    comment_line = "     * %s" % line.strip()
                    comment_info += comment_line.rstrip() + "\n"

            if self.stderr:
                comment_info += "     *\n"
                comment_info += "     * check stderr:\n"
                for line in self.stderr.split("\n"):
                    comment_line = "     * %s" % line.strip()
                    comment_info += comment_line.rstrip() + "\n"

        comment_footer = "     */\n"
        comment = comment_header + comment_info + comment_footer

        # Actual definition of the constant; needs a "L" so that unsigned
        # values get processed correctly.
        source_template = "    public static final long %s = %sL;\n"
        source_line = source_template % (self.name, self.resolved_value)

        return comment + source_line


def read_lines(file_handle):
    """
    Given a pointer to a file, returns contents of the file as a list,
    removing the trailing whitespace from all lines.
    """

    # readlines() leaves the newline character attached, and in general,
    # we don't care about whitespace at the end. We care about prefixed
    # whitespace when reading the copyright header though, hence rstrip()
    # and not strip().
    return list(map(lambda x: x.rstrip(), file_handle.readlines()))


def parse_token(line, offset):
    """
    From a line, parse a single "token" starting at the given character
    offset. The definition of a token is a continguous, non-whitespace
    segment of characters; parenthesis allow the token to continue over
    whitespace. Returns a tuple (token, index_of_last_character).

    In particular, "(some content)" is treated as a single token,
    "(something else" is an error (lacks a trailing parenthesis), and
    "some content" is two separate tokens.
    """

    # Parenthesis occur when the constant is a compound expression
    # like in the case of CKO_NSS: (CKO_VENDOR_DEFINED | NSSCK_VENDOR_NSS).
    # We need the entire expression to be parsed as a single "value",
    # hence keeping track of parenthesis. Other symbols (such as curly
    # braces or square brackets) are ignored because they don't appear
    # in useful #define statements.

    token_start = offset
    while token_start < len(line) and line[token_start].isspace():
        token_start += 1

    paren_count = 0
    token_end = token_start
    while token_end < len(line) and (not line[token_end].isspace() or
                                     paren_count != 0):
        if line[token_end] == '(':
            paren_count += 1
        if line[token_end] == ')':
            paren_count -= 1
        token_end += 1

    if paren_count != 0:
        raise Exception("Cannot parse line: spans multiple lines: %s" % line)

    token = line[token_start:token_end]
    return token, token_end


def parse_define(line):
    """
    Assuming that this line begins with '#define', parse the two parts of
    the define statement: the name of the define and the value it takes.
    Returns a tuple (name, value).
    """

    if not line.startswith('#define'):
        raise Exception("Cannot parse line: doesn't begin with #define!\n" +
                        line)

    name, name_end = parse_token(line, len('#define'))
    value, _ = parse_token(line, name_end)

    return name, value


def parse_copyright(file_contents):
    """
    In the contents of a file, find all comments before the first macro
    statement and include them in the returned copyright headers.
    """

    in_comment = False
    copyright_headers = []

    # We need to parse the copyright value for legal reasons. While in
    # practice the copyright could be anywhere, we assume it is in the
    # comments before the first macro statement in the file. This makes
    # an attempt to remove blank lines that are not part of a comment,
    # and does basic sanity checking on the locations of block comments.
    # This _will_ get confused as it doesn't completely parse comments,
    # but that confusion should be limited to later in the file, which
    # we ignore.
    for line_num in range(0, len(file_contents)):
        line = file_contents[line_num]

        have_start = "/*" in line
        have_end = "*/" in line
        have_pound = '#' in line

        if have_start and have_end:
            # In this case, both a /* and */ appeared, so we make an effort
            # to detect which came first and update our state accordingly.
            start_index = line.index("/*")
            end_index = line.index("*/")
            start_before_end = start_index < end_index and line.endswith("*/")

            if start_before_end:
                in_comment = False
            else:
                in_comment = True

            # Either way, save the line and hope it is a valid comment :)
            copyright_headers.append(line)
        elif have_start:
            # We're beginning a comment, save this line.
            in_comment = True
            copyright_headers.append(line)
        elif have_end:
            # We're ending a comment, save this line.
            in_comment = False
            copyright_headers.append(line)
        elif in_comment:
            # We're in a comment, save this line.
            copyright_headers.append(line)
        elif not in_comment and have_pound:
            # We're not in a comment, assume the pound means a macro
            # statement and exit.
            break
        # else: we're not in a comment and this is a random line, so don't
        #       bother saving it.

    return "\n".join(copyright_headers) + "\n\n"


def parse_header(header):
    """
    Parse the contents of the file path (header) for #define statements and
    the copyright headers. The #define statements are returned as a list of
    items of type ConstantDefinition. The copyright header is returned as a
    string.
    """

    file_contents = read_lines(header)

    # Capture all definitions first, and create ConstantDefinition from them.
    defines = []
    for line_num in range(1, len(file_contents)+1):
        line = file_contents[line_num-1].lstrip()
        if line.startswith('#define'):
            name, value = parse_define(line)
            new_definition = ConstantDefinition(header.name, line_num, line,
                                                name, value)
            defines.append(new_definition)

    # Also save the copyright headers from this file for legal reasons.
    copyright_headers = "/* Copyright statements from %s */\n" % header.name
    copyright_headers += parse_copyright(file_contents)

    return defines, copyright_headers


def remove_by_name(objs, name):
    """
    Helper function to take a list of objects and remove the occurrences
    of constants with the same name, updating the list in place. This is
    necessary to make our list behave like an ordered set.
    """

    # Build a list of indices where the object occurs; this should be
    # only one index, but we handle the case where it appears multiple
    # times in the list.
    indices = []
    for index in range(0, len(objs)):
        obj = objs[index]
        if obj.name == name:
            indices.append(index)

    # Create a copy of the array and modify the copy; in particular, by
    # removing objects in reversed order, we can ensure that we don't
    # need to update the value of the indices (e.g., if we processed
    # the indices (1, 2, 3), we'd have to subtract one from 2 and 3
    # after processing the first index (1)... this gets messy, so
    # processing in reverse order (3, 2, 1) ensures we don't have to.
    for index in reversed(sorted(indices)):
        objs.pop(index)


def filter_objects(objs):
    """
    From all known defined objects (of type ConstantDefinition), filter
    the output to only contain objects which should be included, i.e.,
    whose name begins with a whitelisted prefix. Return the result as a
    new list.
    """
    results = []

    for obj in objs:
        if obj.is_included():
            # Before appending an object, we must first remove an previous
            # references to it in the results list. This is mostly an issue
            # so that we don't have duplicate definitions in our file, but
            # also because some constants appear multiple times in pkcs11n.h
            # due to GCC deprecation hacks.
            remove_by_name(results, obj.name)
            results.append(obj)
        else:
            # It isn't an error and is merely informational to ignore some
            # symbols at this stage.
            print("Symbol ignored due to unmatched prefix: %s" % obj.name)

    return results


def resolve_internal_references(objs):
    """
    Resolve all internal references between symbols in objs, modifying the
    objects in place. That is, if SYM_A = SYM_B and SYM_B = 3 are of type
    ConstantDefinition, modify them so SYM_A = 3 and SYM_B = 3. This also
    works if the symbol names are inside the value.

    Note that obj.resolve_value must be passed a list of constants ordered
    by reverse alphabetical order on the name of the symbol.
    """

    # To build the sorted order, we're going to use O(2n) space: first
    # build a dictionary mapping everything, and then construct a new
    # list based on the order. This isn't terribly expensive as the
    # objects are small and the O(n log n) sort could/should dominate.
    obj_map = {}
    for obj in objs:
        obj_map[obj.name] = obj

    sorted_objs = []
    for key in reversed(sorted(obj_map.keys())):
        sorted_objs.append(obj_map[key])

    for obj in objs:
        obj.resolve_value(sorted_objs)


def check_references(objs):
    """
    Perform extended checks against all known symbols; this assumes that
    the passed pkcs11t.h and pkcs11n.h are the system-installed version.
    In particular, given our current set of symbols, create a minimal C
    program which checks our computed value against the actual value in
    the header; this ensures all known symbols are parsed correctly.

    Depends on the following external programs being in PATH:
        - pkg-config
        - cc
    """

    # This method just wraps calling obj.check_output() for all constants.

    # Print statement because this step takes a while (~30s); might as well
    # tell the user. :)
    print("Performing extended value checks...")

    # Such that we can link against nss and find the includes, use pkg-config.
    # Note that pkg-config is already a soft-dependency (it is utilized in
    # the README for linking against the system NSS), so using it here
    # isn't bad.
    proc = subprocess.Popen(["pkg-config", "--libs", "--cflags", "nss"],
                            stdout=subprocess.PIPE)
    proc.wait()
    pkg_config = proc.stdout.read()
    if not isinstance(pkg_config, str):
        pkg_config = pkg_config.decode('utf8')

    # Make a safer argument list out of them so we don't need to fork out
    # to the shell.
    nss_args = pkg_config.strip().split(' ')

    for obj in objs:
        obj.check_output(nss_args)


def build_class(objs, headers, verbose):
    """
    From a dictionary of objects (obj_map), generate a Java class for the
    constants. Returns the text contents (str) of the generated class file.
    """

    # Our generated Java class has the following structure:
    #
    # - Our Copyright and information block
    # - Our headers copyright blocks
    # - Class definition
    #   - Constant comment
    #   - Constant definition
    #   - ... (repeat)
    # - End class definition
    #
    # Note that our result is a single string, not a list of lines.

    file_header = textwrap.dedent("""\
    /**
     * PKCS11Constants.java - part of the JSS project
     * Copyright (C) 2018 Red Hat, Inc.
     *
     * This file is automatically generated (tools/build_pkcs11_constants.py)
     * from the contents of NSS's pkcs11t.h and pkcs11n.h headers. This
     * replaces the sun.security.pkcs11.wrapper.PKCS11Constants interface
     * which was removed from public visibility in JDK 9 due to the
     * introduction of modules.
     *
     * For more information, please see the documentation under
     * jss/docs/pkcs11_constants.md.
     *
     * Below are the copyright statements for the sourced files:
     */
    """)

    for header in headers:
        file_header += header

    file_header += textwrap.dedent("""\
    package org.mozilla.jss.pkcs11;

    public interface PKCS11Constants {
    """)

    file_body = ""
    for obj in objs:
        file_body += obj.get_source_content(verbose)

    file_footer = "}\n"

    return file_header + file_body + file_footer


def test_compilation(file_contents):
    """
    Given the contents of the generated Java class, try to compile it. This
    allows us to verify that our Java class is valid and doesn't break the
    build.

    Depends on the following programs being in the PATH:
        - javac
    """

    # Since this is a stand-alone package, we don't require CLASSPATH to
    # include anything.

    # Create a temporary directory so we can create a file of the correct
    # name for Java, but also so that in the event of failure, the user
    # can view the file to see what is wrong as we haven't written it
    # to the output location yet.
    java_dir = tempfile.mkdtemp(prefix="tmp-jss-pkcs11constants-")

    java_path = os.path.join(java_dir, "PKCS11Constants.java")
    class_path = java_path.replace(".java", ".class")

    temp_program = open(java_path, 'w')
    temp_program.write(file_contents)
    temp_program.close()

    # The subprocess.call will output stdout/stderr of the called program.
    javac_call = ["javac", java_path]
    ret = subprocess.call(javac_call)
    if ret != 0:
        raise Exception("Error! Generated java code does not compile!")

    # If successful, clean up after ourselves.
    if os.path.exists(class_path):
        os.remove(class_path)

    if os.path.exists(java_path):
        os.remove(java_path)

    if os.path.exists(java_dir):
        os.rmdir(java_dir)


def write_class(file_contents, output):
    """
    Helper method to write the contents of the file to the specified file
    handle (output).
    """
    output.write(file_contents)
    output.close()


def parse_args():
    """
    Parses arguments passed to the application
    """
    parser = argparse.ArgumentParser()

    # This enables the checks against a system-installed NSS; this is slow
    # (~30s) and is hence not enabled by default (and also not possible
    # against a source NSS tree without more work). However it is useful for
    # verifying our parsing routines.
    parser.add_argument("-s", "--system", action="store_true",
                        help="pkcs11t.h is installed; perfrom system checks")

    # This is the path to the pkcs11t.h header file from the NSS we wish to
    # build against. pkcs11t.h is the main header which contains most of the
    # RSA/"Cryptoki" values.
    parser.add_argument("--pkcs11t", type=argparse.FileType('r'),
                        required=True, help="Path to pkcs11t.h header")

    # This is the path to the pkcs11n.h header file from the NSS we whish to
    # build against. pkcs11n.h is the header which contains NSS/Netscape
    # specific values.
    parser.add_argument("--pkcs11n", type=argparse.FileType('r'),
                        required=True, help="Path to pkcs11n.h header")

    # Path to output the generated file to.
    parser.add_argument("-o", "--output", type=argparse.FileType('w'),
                        required=True,
                        help="Path to write PKCS11Constants.java")

    # Enables verbose or debugging mode, which writes additional information
    # to the generated output.
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Write verbose comments in output")


    return parser.parse_args()


def main():
    """
    Main method for utility parser.
    """
    args = parse_args()

    # The high level flow of the program is as follows:
    #
    # - Parse the pkcs11t header
    # - Parse the pkcs11n header
    # - Combine the resulting definitions in that order
    # - Resolve internal references/convert symbols to numeric values
    # - If extended checks are requested, run them
    # - Check that the generated class compiles
    # - Write the generated class as output
    #
    # The philosophy of this utility is anything that is a "warning" should
    # instead be treated as an error, with the exception of compiler warnings
    # when performing extended system checks. All exceptions are raised as
    # exceptions, and are not caught by this main method and thus will be
    # reported to the caller as the occur. This ensures that the output won't
    # be malformed and won't be generated unless it is correct.
    #
    # In particular:
    #
    # - All #define statements are considered constant definitions.
    # - If a #define cannot be parsed, this is an error.
    # - If a symbol value cannot be resolved to a numeric value, this is
    #   an error.
    # - If a parsed value is not the same as the system version, this is
    #   an error.
    # - If the resulting Java program does not compile, this is an error.

    t_objs, t_copyright = parse_header(args.pkcs11t)
    t_objs_filtered = filter_objects(t_objs)

    n_objs, n_copyright = parse_header(args.pkcs11n)
    n_objs_filtered = filter_objects(n_objs)

    objs = t_objs_filtered[:]
    objs.extend(n_objs_filtered)
    headers = [t_copyright, n_copyright]

    resolve_internal_references(objs)

    if args.system:
        # Since this is a system call, ignore the paths to the headers and
        # assume they are the same as what is found by pkg-config.
        check_references(objs)

    output_contents = build_class(objs, headers, args.verbose)
    test_compilation(output_contents)

    write_class(output_contents, args.output)

    print("Success generating constant definitions")


if __name__ == "__main__":
    main()
