GET DATA /TYPE=TXT /FILE='../data/small.csv' /DELIMITERS=','.
T-TEST GROUPS=group('a' 'b') /VARIABLES=score.
