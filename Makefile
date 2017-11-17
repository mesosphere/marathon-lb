all: package
change-version:
	echo "Modifying version to: $(version)"
	echo $(version) > VERSION
package:
	bin/package.sh

