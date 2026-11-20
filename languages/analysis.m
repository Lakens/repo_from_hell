d = readtable('../data/small.csv');
[h, p] = ttest2(d.score(d.group == "a"), d.score(d.group == "b"))
