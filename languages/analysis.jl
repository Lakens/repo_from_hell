using CSV, DataFrames
d = CSV.read("../data/small.csv", DataFrame)
println(describe(d))
