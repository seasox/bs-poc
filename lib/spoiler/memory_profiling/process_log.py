from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import numpy as np

def plot_diff_store_time(log_file_path, save_path):
    diff_store_times = []

    # Read the log file
    with open(log_file_path, 'r') as file:
        # Skip the header
        next(file)
        # Read each line in the file
        for line in file:
            # Split the line by comma and get the last element
            diff_store_time = int(line.strip().split(',')[-1])
            diff_store_times.append(diff_store_time)

    # Convert the list to a NumPy array and reshape it for k-means
    diff_store_times = np.array(diff_store_times)

    # remove any values above 1000
    #diff_store_times = diff_store_times[diff_store_times < 1000]

    # Reshape the data for k-means
    data = diff_store_times.reshape(-1, 1)

    # Apply K-means clustering
    kmeans = KMeans(n_clusters=3, random_state=0).fit(data)
    
    # Predict the cluster for all data points
    y_pred = kmeans.predict(data)
    
    # Calculate the minimum value of each cluster
    min_cluster_0 = min(data[y_pred == 0])
    min_cluster_1 = min(data[y_pred == 1])
    min_cluster_2 = min(data[y_pred == 2])
    max_cluster_0 = max(data[y_pred == 0])
    max_cluster_1 = max(data[y_pred == 1])
    max_cluster_2 = max(data[y_pred == 2])
    
    print(f'Minimum value of Cluster 0: {min_cluster_0}')
    print(f'Maximum value of Cluster 0: {max_cluster_0}')
    print(f'Minimum value of Cluster 1: {min_cluster_1}')
    print(f'Maximum value of Cluster 1: {max_cluster_1}')
    print(f'Minimum value of Cluster 2: {min_cluster_2}')
    print(f'Maximum value of Cluster 2: {max_cluster_2}')

    # Plot the data with different colors for each cluster
    plt.scatter(np.linspace(len(diff_store_times), 0, len(diff_store_times)), diff_store_times, c=y_pred, cmap='viridis')
    plt.xlabel('Index')
    plt.ylabel('Diff Store Time')
    plt.title('Diff Store Time vs. Index with K-means Clusters')
    plt.colorbar(label='Cluster')
    
    # Save the plot
    plt.savefig(save_path)
    plt.show()


def compute_second_derivative(inertia_points):
    # Compute the second derivative
    second_derivative = []
    for i in range(2, len(inertia_points) - 1):
        diff = (inertia_points[i] - inertia_points[i - 1]) / (inertia_points[i + 1] - inertia_points[i])
        second_derivative.append(diff)
    
    return second_derivative

def plot_second_derivative(inertia_points, n_std_dev=1):
    # Compute the second derivative
    second_derivative = compute_second_derivative(inertia_points)
    
    # Compute mean and standard deviation
    mean = np.mean(second_derivative)
    std_dev = np.std(second_derivative)
    
    # Find the elbow point
    elbow_point = 0
    for i, value in enumerate(second_derivative):
        if value > mean + n_std_dev * std_dev:
            elbow_point = i + 2  # +2 to adjust for the index in the second_derivative list
            break
    
    # Plot the second derivative
    plt.figure(figsize=(10, 6))
    plt.plot(range(2, len(inertia_points) - 1), second_derivative, marker='o', label='Second Derivative')
    plt.axhline(y=mean, color='r', linestyle='--', label='Mean')
    plt.axhline(y=mean + n_std_dev * std_dev, color='g', linestyle='--', label=f'Mean + {n_std_dev} STD DEV')
    plt.xlabel('Number of Clusters')
    plt.ylabel('Second Derivative of Inertia')
    plt.title('Second Derivative of Inertia and Elbow Point Detection')
    plt.legend()
    plt.grid(True)
    plt.savefig('graphs/second_derivative.png', dpi=300)
    
    return elbow_point

def bank_clustering_and_plot(file_path):
    # Initialize lists to store the data and indices from the second column
    data = []
    indices = []
    cluster_indices = []
    
    # Read the file line by line and extract the second column
    with open(file_path, 'r') as file:
        for index, line in enumerate(file):

            # skip the headers
            if index == 0:
                continue

            # Split each line into components and append the second column to the list
            components = line.strip().split(',')
            abs_store_time = int(components[4])
            bank = int(components[2])
            if abs_store_time != 0:  # Exclude outliers (zero values)
                data.append(abs_store_time)
                indices.append(index)
                cluster_indices.append(bank)
    
    # graph
    plt.figure(figsize=(10, 6))
    plt.scatter(indices, data, c=cluster_indices, cmap='viridis')
    plt.xlabel('Index')
    plt.ylabel('Cycles (Higher values indicate physical hazard)')
    plt.title('Bank Clustering of the Data from Spoiler+ Timing')
    plt.colorbar(label='Cluster Index')
    plt.grid(True)
    plt.savefig('graphs/bank_clustering.png', dpi=300)



def kmeans_clustering_and_plot(file_path, n_clusters):
    # Initialize lists to store the data and indices from the second column
    data = []
    indices = []
    
    # Read the file line by line and extract the second column
    with open(file_path, 'r') as file:
        for index, line in enumerate(file):

            # skip the headers
            if index == 0:
                continue

            # Split each line into components and append the second column to the list
            components = line.strip().split(',')
            abs_store_time = int(components[4])
            if abs_store_time != 0:  # Exclude outliers (zero values)
                data.append(abs_store_time)
                indices.append(index)

    data = data[1000:]
    indices = indices[1000:]
    
    # Convert the list to a NumPy array and reshape it for k-means
    data = np.array(data).reshape(-1, 1)

    inertia_points = []
    
    for i in range(1, n_clusters):
        # Apply K-means clustering
        kmeans = KMeans(n_clusters=i, random_state=0).fit(data)
        
        # Predict the cluster for all non-outlier data points
        y_pred = kmeans.predict(data)

        # Calculate and print the inertia (sum of squared distances to the closest centroid)
        print(f'Inertia: {kmeans.inertia_}')

        # Store the inertia for plotting
        inertia_points.append(kmeans.inertia_)

    # Plot the inertia points
    
    plt.figure(figsize=(10, 6))
    plt.plot(range(1, n_clusters), inertia_points, marker='o')
    plt.xlabel('Number of Clusters')
    plt.ylabel('Inertia')
    plt.title('Inertia of K-means Clustering')
    plt.grid(True)
    plt.savefig('graphs/kmeans_inertia.png', dpi=300)
    


    # Compute the elbow point
    elbow_point = plot_second_derivative(inertia_points)
    print(f'Elbow Point: {elbow_point}')


    
    # Plotting
    plt.figure(figsize=(10, 6))
    
    # Assign different colors for each cluster
    colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k']

    # Plot each cluster
    for i in range(n_clusters):
        # Select only data points with cluster label == i
        cluster_indices = [indices[j] for j in range(len(indices)) if y_pred[j] == i]
        dp_cluster = data[y_pred == i]
        plt.scatter(cluster_indices, dp_cluster.squeeze(), c=colors[i % len(colors)], label=f'Cluster {i}')


  
    
    # Labels and title
    plt.xlabel('Index')
    plt.ylabel('Cycles (Higher values indicate physical hazard)')
    plt.title('K-means Clustering of the Data from Spoiler+ Timing')
    plt.legend()
    plt.grid(True)
    plt.savefig('graphs/kmeans_clustering.png', dpi=300)

# Replace 't2.txt' with your actual file path and set the number of clusters you wish to find

#kmeans_clustering_and_plot('logs/spoiler.csv', n_clusters=30)
#bank_clustering_and_plot('logs/spoiler.csv')

plot_diff_store_time('logs/spoiler.csv', 'graphs/diff_store_time.png')