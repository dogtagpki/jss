srpm:
	dnf install -y git
	./build.sh --with-timestamp --with-commit-id srpm
	if [[ "${outdir}" != "" ]]; then \
	    mv ${HOME}/build/jss/SRPMS/* ${outdir}; \
	fi
