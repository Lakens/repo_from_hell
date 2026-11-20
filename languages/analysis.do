import delimited "../data/small.csv", clear
ttest score, by(group)
regress score i.group
