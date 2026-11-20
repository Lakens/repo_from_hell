d <- read.csv("data/small.csv")
t.test(score ~ group, data = d)
