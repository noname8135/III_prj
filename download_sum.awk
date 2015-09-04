#!/bin/awk
IF $7>0 && $9>0 {
    if (sum[$2]>0) {
      sum[$2] += $9
    }
    else {
      sum[$2] = $9
    }
} 
END{
  for(i in sum)
    if (sum[i]>t)
    print i"\t"sum[i]
}
