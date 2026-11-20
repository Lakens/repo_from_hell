proc import datafile='../data/small.csv' out=d dbms=csv replace; run;
proc ttest data=d; class group; var score; run;
