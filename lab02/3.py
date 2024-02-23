import math

prob = 0
for i in range(12, 60 + 1):
    prob += math.comb(60, i) * 4 ** (60 - i)
prob /= 5 ** 60
print(prob)