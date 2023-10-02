import matplotlib.pyplot as plt

# Read data from the text file
with open("spoiler_timings.txt", "r") as file:
    data = [int(line.strip()) for line in file]

# Create a line graph
plt.plot(data, marker='o', linestyle='-')

# Add labels and a title
plt.xlabel("Data Point Index")
plt.ylabel("Value")
plt.title("Line Graph from Text File Data")

# Show the graph
plt.grid(True)
plt.tight_layout()
plt.show()