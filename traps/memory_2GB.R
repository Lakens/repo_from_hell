x <- list()
for (i in 1:20) x[[i]] <- numeric(1.25e7)  # 100 MB each
print(object.size(x), units = 'GB')
