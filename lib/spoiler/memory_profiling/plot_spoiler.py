import pandas as pd
import matplotlib.pyplot as plt

# Load the data from the CSV file
file_path = 'logs/spoiler_cluster.csv'  # Replace with your file path
data = pd.read_csv(file_path)

# Creating the scatter plot
plt.figure(figsize=(12, 6))
plt.scatter(data['index'], data['diffBuffer'], c=data['cluster'], cmap='viridis')

# Adding titles and labels
plt.title('Scatter Plot of diffBuffer vs. Index with Cluster Color Coding')
plt.xlabel('Index')
plt.ylabel('diffBuffer')
plt.colorbar(label='Cluster')

# Show the plot
plt.savefig("spoiler_clusters.png")
