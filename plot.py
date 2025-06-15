import numpy as np
import matplotlib.pyplot as plt

data = {(1, 8, 8): [7.97, 315, 0], (0.5, 8, 8): [15.83, 1272, 0], (0.33, 8, 8): [23.86, 3212, 0], (0.32, 8, 8): [24.55, 923, 1], (0.31, 8, 8): [0.026, 953, 952], 
        (1, 9, 8): [2.36, 553, 407], (0.5, 9, 8): [6.57, 1149, 725], (0.33, 9, 8): [11.25, 690, 401], (0.32, 9, 8): [11.73, 923, 531],
        (0.31, 14, 14): [0.036, 2443, 2441], (0.32, 14, 14): [43.02, 923, 0], (0.33, 14, 14): [41.7, 2527, 0], (0.5, 14, 14): [27.68, 1181, 2], (1, 14, 14): [13.93, 746, 0], 
        (1, 15, 15): [13.89, 565, 39], (0.5, 15, 15): [26.91, 1121, 102], (0.33, 15, 15): [40.11, 1668, 163], (0.32, 15, 15): [42.16, 924, 79], 
        (0.33, 16, 16): [30.02, 930, 345], (0.5, 16, 16): [17.19, 713, 326], (1, 16, 16): [10.63, 519, 172], 
        (1, 17, 17): [6.88, 462, 274], (0.5, 17, 17): [12.13, 722, 462], (0.33, 17, 17): [14.99, 1252, 882],
        (0.31): [6270, 6268], (0.32): [20523, 711], (0.33): [2154, 1], (0.5): [902, 0], (1): [362, 0], 
        }

TP = 0
FP = 0
TN = 0
FN = 0

for keys in data.keys():
    print(keys)
    if type(keys) is tuple:
        FN += data[keys][1] - data[keys][2]
        TP += data[keys][2]
    else:
        TN += data[keys][0] - data[keys][1]
        FP += data[keys][1]

print(f"TP: {TP}, FN: {FN}, TN: {TN}, FP: {FP}")
print(f"F1 Score: {TP/(TP + (FP + FN)*0.5)}")

for idx, i in enumerate([1,0.5,0.33,0.32,0.31]):
    plt.figure(idx)
    plt.title(f"Covert Channel Achieved Bandwidth when Interval = {i}s")
    plt.ylabel("Achieved Bandwidth (bps)")
    plt.xlabel("Number of Covert Bits in usecs Field")
    plt.plot([u for u in [8, 14, 15, 16, 17] if data.get((i, u, u)) is not None], [data.get((i, u, u))[0] for u in [8, 14, 15, 16, 17] if data.get((i, u, u)) is not None])
    plt.savefig(f"results/covert_i{i}.png")

plt.figure(idx+1)
plt.title("Covert Channel Achieved Bandwidth when Covert Bits in usecs Field = 8")
plt.ylabel("Achieved Bandwidth (bps)")
plt.xlabel("Packet Interval (s)")
plt.plot([1,0.5,0.33,0.32,0.31], [data.get((i, 8, 8))[0] for i in [1,0.5,0.33,0.32,0.31]])
plt.savefig(f"results/covert_u8s8.png")

plt.figure(idx+2)
plt.title("Covert Channel Achieved Bandwidth when Covert Bits in usecs Field = 8 an secs Field = 1")
plt.ylabel("Achieved Bandwidth (bps)")
plt.xlabel("Packet Interval (s)")
plt.plot([1,0.5,0.33,0.32], [data.get((i, 9, 8))[0] for i in [1,0.5,0.33,0.32]])
plt.savefig(f"results/covert_u8s9.png")

# plt.show()
