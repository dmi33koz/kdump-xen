BEGIN {
	print "#ifndef KDUMP_HYPERCALL_NAMES_H";
	print "#define KDUMP_HYPERCALL_NAMES_H";
	print "";
	print "const char *hypercall_names[] = {";
};

/^\#define __HYPERVISOR_\w+[[:space:]]+[[:digit:]]+$/ { print "\t[" $3 "] = \"" $2 "\"," };

END {
	print "};";
	print "";
	print "#endif";
};
