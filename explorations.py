#%%
from IPython.display import display, Image
import pandas
import json
pandas.set_option('display.max_columns', 500)
pandas.set_option('display.width', 1000)

#%%

# Use Python's JSON lib, because Pandas doesn't provide
# an option to not cast floats.
# This is a problem when you have discrete categories
# (in this case, severity 1.7) that Pandas introduces
# floating-point drift to.
cves = None
for i in range(2,20):
	path = f'./data/nvdcve-1.1-20{i:02}.json'
	with open(path, 'r') as f:
		print(f'Loading {path} ... ({i-1} of {len(range(2,20))})')
		data = json.load(f)

	if cves is None: cves = pandas.DataFrame(data)
	else: cves = cves.append(pandas.DataFrame(data))
	print(f'Loaded {path}. New shape: {cves.shape}')
# cve20022 = pandas.read_json('./data/nvdcve-1.1-2002.json', dtype=False)
# iseq = cve2002==cve20022
# for col in iseq.columns:
# 	print(iseq[col].value_counts())

# #%%
# a = str(cve2002[cve2002['CVE_Items'] != cve20022['CVE_Items']].iloc[0,5])

# #%%
# b = str(cve20022[cve2002['CVE_Items'] != cve20022['CVE_Items']].iloc[0,5])

# #%%
# a == b
# b
print(cves.shape)
cves.tail(10)


#%%
normalized = pandas.io.json.json_normalize(cves['CVE_Items'])
del cves

#%%
print(normalized.shape)
normalized.head(10)

#%%
pre_dropped = normalized.copy()

normalized.dropna(subset=['impact.baseMetricV2.cvssV2.version'], inplace=True)

#%%
to_drop = ['CVE-2018-10662', 
			'CVE-2018-10658', 
			'CVE-2018-10659',
			'CVE-2018-10661',
			'CVE-2018-10664',
			'CVE-2018-10663',
			'CVE-2018-10660']
for cve in to_drop:
	print(normalized[normalized['cve.CVE_data_meta.ID']==cve]['configurations.nodes'].iloc[0])
	normalized = normalized[normalized['cve.CVE_data_meta.ID']!=cve]

#%%
normalized.isna().sum()

#%%
normalized['configurations.nodes'].head(20)

#%%
normalized['cve.CVE_data_meta.ID'].tail()

#%%

# print(normalized['configurations.nodes'][0][0])
# df = pandas.io.json.json_normalize(normalized['configurations.nodes'][0][0]['cpe_match'])
df_1 = normalized.explode('configurations.nodes')
del normalized
def get_from_key(d, key=None, default=None):
	if not isinstance(d, dict):
		return(d)
	return(d.get(key, default))
def get_modified(d, key='cpe_match', child_key='children', default=None):
	if not isinstance(d, dict):
		return(d)
	if key in d:
		return(d.get(key, default))
	elif child_key in d:
		if isinstance(d[child_key], dict):
			return(get_from_key(d, key=key, default=default))
		elif isinstance(d[child_key], list):
			ret = []
			for val in d[child_key]:
				v = get_from_key(val, key=key, default=default)
				if isinstance(v, list):
					ret += v
				else:
					ret.append(v)
			return(ret)
		else:
			return(d[child_key])
df_1['cpe_match'] = df_1['configurations.nodes'].apply(get_modified)

#%%
# a = {'operator': 'AND',
#  'children': [{'operator': 'OR',
#    'cpe_match': [{'vulnerable': True,
#      'cpe23Uri': 'cpe:2.3:o:cisco:ios:7000:*:*:*:*:*:*:*'}]},
#   {'operator': 'OR',
#    'cpe_match': [{'vulnerable': True,
#      'cpe23Uri': 'cpe:2.3:a:gnu:inet:5.01:*:*:*:*:*:*:*'},
#     {'vulnerable': True,
#      'cpe23Uri': 'cpe:2.3:a:microsoft:winsock:2.0:*:*:*:*:*:*:*'}]}]}

# b = []
# b+=get_from_key(a['children'][0],key='cpe_match')
# b

#%%
df = df_1.explode('cpe_match')
del df_1
df['cpe23Uri'] = df['cpe_match'].apply(get_from_key, key='cpe23Uri')
df['vulnerable'] = df['cpe_match'].apply(get_from_key, key='vulnerable')

#%%
print(df.shape)
df.tail(20)

#%%
# df['cpe23Uri'].str.count(':').value_counts()
# No escaped colons, despite them being legal in CPE 2.3 URIs
# see https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
# Thank goodness, that simplifies things greatly
#
# Scratch that prior note. See regex below.
# 

#%%
# def get_vendor(s):
# 	if not isinstance(s, str): return(s)
# 	return(s.split(':')[3])
# def get_product(s):
# 	if not isinstance(s, str): return(s)
# 	return(s.split(':')[4])
# df['vendor'] = df['cpe23Uri'].apply(get_vendor)
# df['product'] = df['cpe23Uri'].apply(get_product)
vp = df['cpe23Uri'].str.extract(r'(?P<cpe_version>cpe:2\.3:)(?P<part>[aho])(?P<vendor>(?::(?:[a-zA-Z0-9!"#$%&\'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+))(?P<product>(?::(?:[a-zA-Z0-9!"#$%&\'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+))(?P<additional_fields>(?::(?:[a-zA-Z0-9!"#$%&\'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+){8})$', expand=True)

for column in vp.columns:
	df[column] = vp[column]

del vp

#%%
df['vendor'].isna().sum()


#%%
df['vendor'].value_counts()

#%%
df[df['vendor']==':aol'].groupby('cve.CVE_data_meta.ID').first()

# #%%
# df[df.isna()['cpe_match']==True].head(1).loc[15,'configurations.nodes']
# #%%
# df[df.isna()['cpe_match']==True].head().iloc[1].loc['configurations.nodes']

#%%
print(df.shape)
df['vendor'].isna().sum()

#%%

# df[df['cpe23Uri'].str.find('\\\\')>-1]

#%%
# vp.head(10)

#%%
print(df.shape)
# print(vp.shape)

#%%
df[df['vendor']==':axis'].loc[107647,'configurations.nodes'].iloc[-15]
# 2129786
# https://blog.vdoo.com/2018/06/18/vdoo-discovers-significant-vulnerabilities-in-axis-cameras/

#%% [markup]
#
#
# df[df['publishedDate']=='2018-06-26T18:29Z']['vendor'].value_counts()
# :axis       2129400
# :siemens         54
# :redhat           2
# :ovirt            2
# Name: vendor, dtype: int64
#
#
# df[df['publishedDate']=='2018-06-26T18:29Z']['cve.CVE_data_meta.ID'].value_counts()
# CVE-2018-10662    304200
# CVE-2018-10658    304200
# CVE-2018-10659    304200
# CVE-2018-10661    304200
# CVE-2018-10664    304200
# CVE-2018-10663    304200
# CVE-2018-10660    304200
# CVE-2018-4846         21
# CVE-2018-4845         21
# CVE-2018-1072          4
# CVE-2018-11447         2
# CVE-2018-11448         2
# CVE-2018-4860          2
# CVE-2018-4861          2
# CVE-2018-4859          2
# CVE-2018-11449         2
# Name: cve.CVE_data_meta.ID, dtype: int64

#%%
# df[df['publishedDate']=='2018-06-26T18:29Z'].loc['CVE-2018-10660','cve.CVE_data_meta.ID'].value_counts()

#%%
#qualcomm
#mozilla
#apple
#microsoft
#
chrome_points_awry, [] = df[(df['product']==':chrome') & (df['vendor']==':google') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first()['publishedDate'].str[:4].value_counts().sort_index()

chrome_points = df[(df['product']==':chrome') & (df['vendor']==':google') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first().index.str[4:8].value_counts().sort_index()

#%%
# publishedDate has the wrong data for Firefox
# so we use the year in the CVE ID instead
# Then do the same for other browsers for consistency's sake
# it makes more sense anywho, as the publication date can vary wildly
# depending on notice given etc.
firefox_points = df[(df['product']==':firefox') & (df['vendor']==':mozilla') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first().index.str[4:8].value_counts().sort_index()

firefox_points_awry, [] = df[(df['product']==':firefox') & (df['vendor']==':mozilla') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first()['publishedDate'].str[:4].value_counts().sort_index()
#.str[4:9].value_counts()

#%%
firefox_points
#%%
firefox_points_awry, []

#%%
safari_points_awry, [] = df[(df['product']==':safari') & (df['vendor']==':apple') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first()['publishedDate'].str[:4].value_counts().sort_index()
safari_points = df[(df['product']==':safari') & (df['vendor']==':apple') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first().index.str[4:8].value_counts().sort_index()

#%%
# ie_points

#%%
# df[(df['product']==':edge') & (df['vendor']==':microsoft')].groupby('cve.CVE_data_meta.ID').first()
#%%
ie_points_awry, [] = df[(df['product']==':ie') & (df['vendor']==':microsoft') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first()['publishedDate'].str[:4].value_counts().sort_index()
ie_points = df[(df['product']==':ie') & (df['vendor']==':microsoft') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first().index.str[4:8].value_counts().sort_index()
#%%
edge_points_awry, [] = df[(df['product']==':edge') & (df['vendor']==':microsoft') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first()['publishedDate'].str[:4].value_counts().sort_index()
edge_points = df[(df['product']==':edge') & (df['vendor']==':microsoft') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first().index.str[4:8].value_counts().sort_index()

#%%

# This could be done more elegantly
years = range(1996, 2020)
browser_ys = {	'Chrome': [chrome_points, [], 'b', chrome_points_awry, []],
				'Firefox': [firefox_points, [], 'r', firefox_points_awry, []],
				'Internet Explorer': [ie_points, [], 'white', ie_points_awry, []],
				'Safari': [safari_points, [], 'g', safari_points_awry, []],
				'Edge': [edge_points, [], 'magenta', edge_points_awry, []]}
for browser in browser_ys:
	for year in years:
		if str(year) in browser_ys[browser][0]:
			browser_ys[browser][1].append(browser_ys[browser][0][str(year)])
		else:
			browser_ys[browser][1].append(0)

		if str(year) in browser_ys[browser][3]:
			browser_ys[browser][4].append(browser_ys[browser][3][str(year)])
		else:
			browser_ys[browser][4].append(0)

browser_ys['Firefox'][1]

#%%
import matplotlib.pyplot as pyplot
pyplot.rcParams['figure.facecolor'] = '#002B36'
pyplot.rcParams['axes.facecolor'] = 'black'

for browser in browser_ys:
	pyplot.plot(years, browser_ys[browser][1], browser_ys[browser][2], label=browser)
# pyplot.plot(ie_points, color='turquoise', label='Internet Explorer')
# pyplot.plot(firefox_points, color='r', label='Firefox')
# pyplot.plot(chrome_points, color='b', label='Chrome')
# pyplot.plot(safari_points, color='g', label='Safari')
# pyplot.plot(edge_points, color='magenta', label='Edge')
pyplot.legend()
pyplot.title('CVEs by year for different browsers, by CVE ID')
pyplot.xlabel('Year')
pyplot.ylabel('Number of CVEs')
figure = pyplot.gcf()
figure.set_size_inches((12,10))
pyplot.show()

for browser in browser_ys:
	pyplot.plot(years, browser_ys[browser][4], browser_ys[browser][2], label=browser)
# pyplot.plot(ie_points, color='turquoise', label='Internet Explorer')
# pyplot.plot(firefox_points, color='r', label='Firefox')
# pyplot.plot(chrome_points, color='b', label='Chrome')
# pyplot.plot(safari_points, color='g', label='Safari')
# pyplot.plot(edge_points, color='magenta', label='Edge')
pyplot.legend()
pyplot.title('CVEs by year for different browsers, by publication date')
pyplot.xlabel('Year')
pyplot.ylabel('Number of CVEs')
figure = pyplot.gcf()
figure.set_size_inches((12,10))
pyplot.show()

#%%
# df[(df['product']==':firefox') & (df['vendor']==':mozilla') & (df['vulnerable']==True)].groupby('cve.CVE_data_meta.ID').first()

#%%
# import matplotlib.pyplot as pyplot
# pyplot.

#%%
