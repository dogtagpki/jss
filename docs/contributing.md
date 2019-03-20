# Contributing to JSS

We welcome all contributions to JSS and thank you in advance for them! Below
are a few ways of contributing to JSS.


## Filing a Downstream Issue

If you're using JSS as shipped by a distribution, we recommend filing an issue
downstream first. In the case of a [RHCS](https://www.redhat.com/en/technologies/cloud-computing/certificate-system),
[RHEL](https://www.redhat.com/en/technologies/cloud-computing/certificate-system),
or [Fedora](https://getfedora.org/) release, the correct bugtracker is the
[Red Hat Bugzilla](https://bugzilla.redhat.com/) instance.

If you don't hear a response at the appropriate downstream tracker or if you
think the issue exists upstream as well, feel free to file an upstream issue.


## Filing an Upstream Issue

Most of the [Dogtag](https://github.com/dogtagpki) software (the new home of
JSS) uses Fedora's [pagure.io](https://pagure.io/) for bug tracking; JSS's
issue tracker can be found [there](https://pagure.io/jss/issues) as well.
Note that this requires a Fedora account to create bugs. If this isn't of
interest to you, feel free to file an issue on
[GitHub](https://github.com/dogtagpki/jss/issues) instead; it will still get
read and responded to.


## Opening a Pull Request

If you'd like to contribute code to JSS, feel free to open a pull request
against JSS. We'd recommend filing an issue (see above) if you'd like to
introduce major change to JSS. This gives us a place to discuss the changes
before they are proposed.

Please fork the repository and make your changes in a new branch; before
proposing the pull request, rebase your branch against upstream master.
To test JSS locally, follow the [build instructions](building.md).
Additionally, it is possible to run the CI container instances locally;
follow directions in the [CI Overview](ci.md). We'd suggest making
sure a Fedora build passes (e.g., `fedora_28`) and the `stylecheck`
image passes as well. Then, feel free to open a PR.

If you're looking for more information, we suggest reading about the
[GitHub Flow](https://guides.github.com/introduction/flow/index.html)
and reaching out to the developers if you need any assistance.


## Contacting Us

If you wish to discuss contributing to JSS or an issue, there are a few
forums of discussion:

 - The [pki-devel mailing list](https://www.redhat.com/mailman/listinfo/pki-devel).
 - The `#dogtag-pki` IRC channel on [Freenode](https://freenode.net/).

Thanks!
