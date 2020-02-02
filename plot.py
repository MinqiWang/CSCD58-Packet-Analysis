import numpy as np
import matplotlib.pyplot as plt


'''
	Plot the CDF graph for the discrete distribution defined by the given params.

	data -- The unique values in this distribution, sorted in ascending order
	cdf_probabilities -- The corresponding CDF probability for each of the unique value, i.e. P(X <= x) for each unique value x

	Resource: https://stackoverflow.com/questions/49661247/plotting-cdf-for-discrete-variable-step-plot-with-alternating-lines
'''
def _plot_cdf(data, cdf_probabilities):
  x = data
  y = cdf_probabilities

  fig, ax = plt.subplots()
  ax.set_facecolor('white')

  # https://matplotlib.org/api/_as_gen/matplotlib.axes.Axes.hlines.html
  ax.hlines(y=y[:-1], xmin=x[:-1], xmax=x[1:],
          color='red', zorder=1)

  # https://matplotlib.org/api/_as_gen/matplotlib.axes.Axes.vlines.html
  ax.vlines(x=x[1:], ymin=y[:-1], ymax=y[1:], color='red',
          linestyle='dashed', zorder=1)
  ax.vlines(x=x[0], ymin=0, ymax=y[0], color='red',
  	      linestyle='dashed', zorder=1)

  ax.scatter(x, y, color='red', s=18, zorder=2)
  ax.scatter(x[1:], y[:-1], color='white', s=18, zorder=2,
           edgecolor='red')
  ax.scatter(x[0], 0, color='white', s=18, zorder=2,
  	       edgecolor='red')
  ax.grid(False)
  ax.set_xlim(x[0]-1, x[-1]+1)
  ax.set_ylim([-0.01, 1.01])

def plot_cdf_and_save(data, fname):
  data = np.array(data)
  X, Y = np.unique(data, return_counts=True)
  Y = np.cumsum(Y).astype(np.double) / data.size
  _plot_cdf(np.log2(X), Y) # Take the log
  plt.savefig(fname)

# Test
#Z = np.random.randint(0,10, 100)
#X, Y = np.unique(Z, return_counts=True)
#Y = np.cumsum(Y).astype(np.double) / Z.size
#_plot_cdf(X, Y)
#plt.savefig("test.png")
