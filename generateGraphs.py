import matplotlib.pyplot as plt
import numpy as np

sizes = [4, 8, 16, 32, 64, 128, 256, 512]
sign_times = [15.431165695, 27.651548386, 55.190324783, 111.509084702, 227.240562439, 438.945531845, 1260.081768036, 1757.057905197]
vrfy_times = [12.089729309, 23.400783539, 42.681932449, 87.990760803, 175.244808197, 358.365297318, 711.171627045, 1424.437046051]
revoke_times = [3.529787064, 6.209135056, 12.527227402, 25.843620300, 49.247503281, 97.371101379, 192.212343216, 390.582084656]

plt.plot(sizes, sign_times, label='Sign Time', marker='o')
plt.plot(sizes, vrfy_times, label='Verify Time', marker='o')
plt.plot(sizes, revoke_times, label='Revoke Time', marker='o')

plt.xlabel('Number of Keys')
plt.ylabel('Time (milliseconds)')
plt.title('Ring Signature Performance')
plt.legend()
plt.grid(True)
plt.xscale('log', base=2)  # Set x-axis to log scale, base 2
plt.yscale('log', base=2)  # Set y-axis to log scale, base 2
plt.show()

import matplotlib.pyplot as plt
import numpy as np

sizes = [4, 8, 16, 32, 64, 128, 256, 512]
sign_times = [6.006240845, 9.991407394, 20.497560501, 39.990901947, 79.516887665, 153.086662292, 318.163156509, 595.035552979]
vrfy_times = [4.995107651, 9.997367859, 21.008014679, 39.528369904, 82.006931305, 150.081157684, 307.644367218, 569.375753403]
revoke_times = [0.999212265, 1.007795334, 1.007556915, 0.994443893, 0.994443000, 0.994443893, 0.994443800, 0.994443700]

plt.plot(sizes, sign_times, label='Sign Time', marker='o')
plt.plot(sizes, vrfy_times, label='Verify Time', marker='o')
plt.plot(sizes, revoke_times, label='Revoke Time', marker='o')

plt.xlabel('Number of Keys')
plt.ylabel('Time (milliseconds)')
plt.title('Ring Signature Performance')
plt.legend()
plt.grid(True)
plt.xscale('log', base=2)  # Set x-axis to log scale, base 2
plt.yscale('log', base=2)
plt.show()

import matplotlib.pyplot as plt

# Ring sizes
sizes = [4, 8, 16, 32, 64, 128, 256, 512]

# RRS 2007 data
sign_times_old = sign_times_ms = [
    42.454242706,
    69.298028946,
    148.515939713,
    298.799753189,
    581.104755402,
    698.699951172,
    1378.798246384,
    2767.722606659
]


vrfy_times_old = verify_times_ms = [
    28.813123703,
    56.848287582,
    117.875337601,
    234.833002090,
    448.765277863,
    555.060863495,
    1122.453689575,
    2239.601373672
]

signature_sizes_kbold = [
    2.41,
    3.98,
    6.96,
    12.67,
    23.95,
    46.01,
    89.96,
    177.19
]



revoke_times_old = [3.529787064, 6.209135056, 12.527227402, 25.843620300, 49.247503281, 97.371101379, 192.212343216, 390.582084656]

# New RRS data
sign_times_new = [19.05989646911621, 40.62843322753906, 72.2208023071289, 151.72600746154785, 325.7412910461426, 634.9849700927734, 996.2503910064697, 1947.2689628601074]
vrfy_times_new = [19.320964813232422, 30.095815658569336, 65.83213806152344, 127.25138664245605, 303.4188747406006, 504.74095344543457, 917.975902557373, 1799.1769313812256]
revoke_times_new = [1.8074512481689453, 1.8513202667236328, 4.791498184204102, 1.5935897827148438, 2.5773048400878906, 1.7278194427490234, 1.9085407257080078, 2.2344589233398438]
signature_sizes_kbnew = [1.2373046875, 1.708984375, 2.658203125, 4.5517578125, 8.3564453125, 15.9482421875, 31.138671875, 61.515625]

sign_times_new2 = [104.80880737304688, 171.5705394744873, 344.8057174682617, 581.3431739807129, 1350.5988121032715, 2672.694206237793, 4821.714878082275, 9595.249652862549]
vrfy_times_new2 = [59.76057052612305, 86.43388748168945, 143.5227394104004, 179.5654296875, 466.34387969970703, 578.6516666412354, 1096.9984531402588, 1928.4226894378662]

# revoke_times_new2 = [0.0016934871673583984, 0.0017979145050048828, 0.0029790401458740234, 0.002247333526611328, 0.0018706321716308594, 0.0025205612182617188, 0.0016627311706542969, 0.0018494129180908203]

signature_sizes_kbnew2 = [1.5322265625, 1.880859375, 2.224609375, 2.5751953125, 2.919921875, 3.2666015625, 3.6123046875, 3.9697265625]

# Plot signing times
# Create a larger square figure
plt.figure(figsize=(8, 15))

# Plot signing times
plt.subplot(3, 1, 1)
plt.plot(sizes, sign_times_old, label="RRS 2007", marker='o')
plt.plot(sizes, sign_times_new, label="Our RRS", marker='o')
plt.plot(sizes, sign_times_new2, label="log-RRS", marker='o')
plt.title("Signing Time Comparison")
plt.xlabel("Ring Size")
plt.ylabel("Time (ms)")
plt.legend()
plt.grid(True)

# Plot verification times
plt.subplot(3, 1, 2)
plt.plot(sizes, vrfy_times_old, label="RRS 2007", marker='o')
plt.plot(sizes, vrfy_times_new, label="Our RRS", marker='o')
plt.plot(sizes, vrfy_times_new2, label="log-RRS", marker='o')
plt.title("Verification Time Comparison")
plt.xlabel("Ring Size")
plt.ylabel("Time (ms)")
plt.legend()
plt.grid(True)

# Plot revocation times
plt.subplot(3, 1, 3)
plt.plot(sizes, revoke_times_old, label="RRS 2007", marker='o')
plt.plot(sizes, revoke_times_new, label="Our RRS", marker='o')
plt.plot(sizes, revoke_times_new, label="log-RRS", marker='o')
plt.title("Revocation Time Comparison")
plt.xlabel("Ring Size")
plt.ylabel("Time (ms)")
plt.legend()
plt.grid(True)


plt.subplot(3, 1, 3)
plt.plot(sizes, signature_sizes_kbold, label="RRS 2007", marker='o')
plt.plot(sizes, signature_sizes_kbnew, label="Our RRS", marker='o')
plt.plot(sizes, signature_sizes_kbnew2, label="log-RRS", marker='o')
plt.title("Signatue Size Comparision")
plt.xlabel("Ring Size")
plt.ylabel("Signature Size in Kb")
plt.legend()
plt.grid(True)

plt.tight_layout()
plt.show()

import matplotlib.pyplot as plt

# Ring sizes
sizes = [4, 8, 16, 32, 64, 128, 256, 512]

# RRS 2007 data
sign_times_old = sign_times_ms = [
    42.454242706,
    69.298028946,
    148.515939713,
    298.799753189,
    581.104755402,
    698.699951172,
    1378.798246384,
    2767.722606659
]


vrfy_times_old = verify_times_ms = [
    28.813123703,
    56.848287582,
    117.875337601,
    234.833002090,
    448.765277863,
    555.060863495,
    1122.453689575,
    2239.601373672
]

signature_sizes_kbold = [
    2.41,
    3.98,
    6.96,
    12.67,
    23.95,
    46.01,
    89.96,
    177.19
]



revoke_times_old = [3.529787064, 6.209135056, 12.527227402, 25.843620300, 49.247503281, 97.371101379, 192.212343216, 390.582084656]

# New RRS data
sign_times_new = [19.05989646911621, 40.62843322753906, 72.2208023071289, 151.72600746154785, 325.7412910461426, 634.9849700927734, 996.2503910064697, 1947.2689628601074]
vrfy_times_new = [19.320964813232422, 30.095815658569336, 65.83213806152344, 127.25138664245605, 303.4188747406006, 504.74095344543457, 917.975902557373, 1799.1769313812256]
revoke_times_new = [1.8074512481689453, 1.8513202667236328, 4.791498184204102, 1.5935897827148438, 2.5773048400878906, 1.7278194427490234, 1.9085407257080078, 2.2344589233398438]
signature_sizes_kbnew = [1.2373046875, 1.708984375, 2.658203125, 4.5517578125, 8.3564453125, 15.9482421875, 31.138671875, 61.515625]

sign_times_new2 = [104.80880737304688, 171.5705394744873, 344.8057174682617, 581.3431739807129, 1350.5988121032715, 2672.694206237793, 4821.714878082275, 9595.249652862549]
vrfy_times_new2 = [59.76057052612305, 86.43388748168945, 143.5227394104004, 179.5654296875, 466.34387969970703, 578.6516666412354, 1096.9984531402588, 1928.4226894378662]

# revoke_times_new2 = [0.0016934871673583984, 0.0017979145050048828, 0.0029790401458740234, 0.002247333526611328, 0.0018706321716308594, 0.0025205612182617188, 0.0016627311706542969, 0.0018494129180908203]

signature_sizes_kbnew2 = [1.5322265625, 1.880859375, 2.224609375, 2.5751953125, 2.919921875, 3.2666015625, 3.6123046875, 3.9697265625]

# Plot signing times
# plt.figure(figsize=(10, 10))
plt.plot(sizes, sign_times_old, label="RRS 2007", marker='o')
plt.plot(sizes, sign_times_new, label="Our RRS", marker='o')
# plt.plot(sizes, sign_times_new2, label="log-RRS", marker='o')
plt.title("Signing Time Comparison")
plt.xlabel("Ring Size")
plt.ylabel("Time (ms)")
plt.legend()
plt.grid(True)
plt.show()

# Plot verification times
# plt.figure(figsize=(10, 10))
plt.plot(sizes, vrfy_times_old, label="RRS 2007", marker='o')
plt.plot(sizes, vrfy_times_new, label="Our RRS", marker='o')
# plt.plot(sizes, vrfy_times_new2, label="log-RRS", marker='o')
plt.title("Verification Time Comparison")
plt.xlabel("Ring Size")
plt.ylabel("Time (ms)")
plt.legend()
plt.grid(True)
plt.show()

# Plot revocation times
# plt.figure(figsize=(10, 10))
plt.plot(sizes, revoke_times_old, label="RRS 2007", marker='o')
plt.plot(sizes, revoke_times_new, label="Our RRS", marker='o')
# plt.plot(sizes, revoke_times_new, label="log-RRS", marker='o')
plt.title("Revocation Time Comparison")
plt.xlabel("Ring Size")
plt.ylabel("Time (ms)")
plt.legend()
plt.grid(True)
plt.show()

plt.plot(sizes, signature_sizes_kbold, label="RRS 2007", marker='o')
plt.plot(sizes, signature_sizes_kbnew, label="Our RRS", marker='o')
# plt.plot(sizes, signature_sizes_kbnew2, label="log-RRS", marker='o')

plt.title("Signature Size Comarision")
plt.xlabel("Ring Size")
plt.ylabel("Size (Kb)")
plt.legend()
plt.grid(True)
plt.show()