{
    if (FNR > 1) {
	if (FNR == 2)
	   for (i = 1; i <= NF; i++)
	       if ($i ~ /(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])(\.(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])){3}/)
	          ip_field[i] = 1
	for (i = 1; i <= NF; i++) {
	    if (i in ip_field)
		if (index($i, "!!!")) {
		   gsub(/!!!/, "", $i)
		   if (i == NF)
		 	printf "%s%s%s\n", $i,FS,"T"
		   else
		        printf "%s%s%s%s", $i,FS,"T",FS
		}
		else if (i == NF)
			printf "%s%s%s\n", $i,FS,"F"
		     else
			printf "%s%s%s%s", $i,FS,"F",FS
	    else
	   	if (i == NF)
		   printf "%s\n", $i
		else
		   printf "%s%s", $i,FS
	}
    }
    else
	print $0
}
