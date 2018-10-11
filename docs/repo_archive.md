# JSS Archive

At the time of migration to GitHub, JSS had collected a significant number of
branches. Because these branches may be of historical importance, it has been
decided to archive them in a separate repository. This allows us to prune the
main repository while persisting this information. For more information on
this decision, please refer to the [RFC](https://pagure.io/jss/issue/25).

To view the JSS archive, navigate to the
[`jss-archive`](https://github.com/dogtagpki/jss-archive) repository. Because
this repository has the same commits as the `jss` repository, it is possible
to use both together:

```
cd /path/to/jss
git remote add jss-archive https://github.com/dogtagpki/jss-archive
git fetch jss-archive
```

At this point, all prior branches and tags will be synchronized with your
current repository. To checkout a retired branch:

```
git checkout jss-archive/BRANCH_NAME
```
