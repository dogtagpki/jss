srpm:
	./build.sh srpm --with-timestamp --with-commit-id
	if [[ "${outdir}" != "" ]]; then \
	    mv ${HOME}/build/jss/SRPMS/* ${outdir}; \
	fi
