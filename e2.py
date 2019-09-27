
#%%
import pandas

df = pandas.read_csv('./data/browser-ww-monthly-200901-201909.csv')
# from https://gs.statcounter.com/browser-market-share#monthly-200901-201909
df.head()

#%%
df.tail()

#%%
df.index=df['Date']

#%%
df['Edge']

# df = df.drop(columns=['Date'])

#%%
import matplotlib.pyplot as pyplot
pyplot.rcParams['figure.facecolor'] = '#002B3600'
pyplot.rcParams['axes.facecolor'] = '#00000000'
COLOR = 'black'
pyplot.rcParams['text.color'] = COLOR
pyplot.rcParams['axes.labelcolor'] = COLOR
pyplot.rcParams['xtick.color'] = COLOR
pyplot.rcParams['ytick.color'] = COLOR
pyplot.rcParams['lines.color'] = COLOR
pyplot.rcParams['grid.color'] = COLOR
pyplot.rcParams['lines.color'] = COLOR
pyplot.rcParams['legend.facecolor'] = '#ffffff19'
# pyplot.rcParams['figure.edgecolor'] = COLOR
pyplot.rcParams['axes.edgecolor'] = COLOR

d = {'Chrome':  'b',
	'Firefox': 'r',
	'IE': 'black',
	'Safari': 'g',
	'Edge': 'magenta'}
for browser in d:
	pyplot.plot(df.index, df[browser], d[browser], label=browser)
# pyplot.plot(ie_points, color='turquoise', label='Internet Explorer')
# pyplot.plot(firefox_points, color='r', label='Firefox')
# pyplot.plot(chrome_points, color='b', label='Chrome')
# pyplot.plot(safari_points, color='g', label='Safari')
# pyplot.plot(edge_points, color='magenta', label='Edge')
pyplot.legend()
pyplot.title('Browser share')
pyplot.xlabel('Year')
pyplot.ylabel('Share (%)')
pyplot.ylim(0,100)
ax = pyplot.gcf().axes[0]
ax.set_xticks(ax.get_xticks()[::12])
pyplot.grid()
figure = pyplot.gcf()
figure.set_size_inches((12,10))
pyplot.show()


#%%
