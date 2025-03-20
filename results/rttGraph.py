import numpy as np
import matplotlib.pyplot as plt

meanDelay = np.array([0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
avgRTT = np.array([7.522, 28.538, 48.590, 71.391, 86.741, 109.093, 123.083, 148.451, 175.655, 192.191, 216.691])

plt.plot(meanDelay,avgRTT)
plt.title("Avg. RTT vs Mean Delay")
plt.ylabel("Avg. RTT (ms)")
plt.xlabel("Mean Delay (ms)")
plt.show()