import pandas as pd
d = pd.read_csv('../data/small.csv')
print(d.groupby('group').score.mean())
