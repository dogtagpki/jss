# GitHub Pages

JSS uses the GitHub pages functionality to host our generated javadocs. This
allows developers to browse our documentation online without pulling down
the JSS sources.

Periodically, this documentation will need to be updated and will mirror the
latest contents of master. To do so:

 1. Checkout the master branch and make sure it is up to date with `upstream`:
    ```
    cd sandbox/jss
    git remote add upstream https://github.com/dogtagpki/jss
    git fetch --all
    git checkout upstream/master
    ```

 2. Build the javadocs; note that they are placed in `../dist/jssdocs`:
    ```
    export JAVA_HOME=/etc/alternatives/java_sdk_1.8.0_openjdk
    export USE_64=1
    make javadoc
    ```

 3. Copy the new-docs into the gh-pages branch:
    ```
    git clean -xdf && git checkout gh-pages
    rm -rf javadoc && cp ../dist/jssdoc javadoc -rv
    git add javadoc && git commit -m "Update javadocs from master at $(date '+%Y-%m-%d %H:%M')" && git push origin gh-pages
    ```

 4. Open a PR against `dogtagpki/jss` with the updates. This will
    get reviewed, merged, and then automatically propagated to
    GitHub Pages.
