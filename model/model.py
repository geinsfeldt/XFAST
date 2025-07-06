import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from sklearn.svm        import OneClassSVM
from sklearn.mixture    import GaussianMixture

# ----------------------------------------------------------
# 1. CSV de origem
# ----------------------------------------------------------

dfs = []
FEATURES = [
    'packets','bytes','max_pkt_len','min_pkt_len','duration',
    'pps','bps','avg_iat','max_iat','min_iat','avg_bpp','var_iat'
]

# Load the datasets
for dirname, _, filenames in os.walk('/home/gus/Downloads/archive/'):
    for filename in filenames:
        dfs.append(pd.read_csv(os.path.join(dirname, filename)))

# Concatenate all DataFrames into a single DataFrame
df = pd.concat(dfs, axis=0, ignore_index=True)

# Deleting DataFrames after merging
for data in dfs: del data

# ----------------------------------------------------------
# 2. Normalize and extract features
# ----------------------------------------------------------
df.rename(columns={c: c.strip() for c in df.columns}, inplace=True)

# Removing rows with statistically irrelevant attack types
df.drop(df[(df['Label'] == 'Infiltration') | (df['Label'] == 'Miscellaneous')].index, inplace=True)

df['packets']     = df['Total Fwd Packets']
df['bytes']       = df['Total Length of Fwd Packets']
df['max_pkt_len'] = df['Fwd Packet Length Max']
df['min_pkt_len'] = df['Fwd Packet Length Min']
df['duration']    = df['Flow Duration'] * 1_000      # µs → ns
df['pps']         = df['Fwd Packets/s']
df['bps']         = df['bytes'] / (df['duration'] / 1e9).replace(0,np.nan)
df['avg_iat']     = df['Fwd IAT Mean']
df['max_iat']     = df['Fwd IAT Max']
df['min_iat']     = df['Fwd IAT Min']
df['avg_bpp']     = df['bytes'] / df['packets'].replace(0, np.nan)
df['var_iat']     = df['Fwd IAT Std'] ** 2

XDP_COLS = [
    'packets','bytes','max_pkt_len','min_pkt_len','duration',
    'pps','bps','avg_iat','max_iat','min_iat','avg_bpp','var_iat'
]

# ----------------------------------------------------------
# 3. Cleaning
# ----------------------------------------------------------
df = df[XDP_COLS + ['Label']]
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df.drop_duplicates(inplace=True)

# ----------------------------------------------------------
# 4. Binarize labels
# ----------------------------------------------------------
df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)
X = df[XDP_COLS].values
y = df['is_attack'].values

# ----------------------------------------------------------
# 5. Split — only train BENIGN
# ----------------------------------------------------------

X_train = X[y == 0]
X_eval  = X
y_eval  = y

# store thresholds -----------------
def save_thresholds(name, lows, highs):
    thr = pd.DataFrame({'feature':FEATURES,'lower':lows,'upper':highs})
    thr.to_csv(f"{name}_thresholds.csv", index=False)
    print(f"\n📁 CSV salvo: {name}_thresholds.csv")
    print(thr.to_string(index=False))

# -------------------------------------------------
# 2‑A. Isolation Forest → thresholds
# -------------------------------------------------
sc_if = StandardScaler().fit(X_train)
iso   = IsolationForest(n_estimators=200,
                        contamination=0.02,
                        random_state=42).fit(sc_if.transform(X_train))

mask = iso.predict(sc_if.transform(X_train)) == 1   # 1 = normal
X_norm = X_train[mask]

low_if  = np.percentile(X_norm, 1 , axis=0)
high_if = np.percentile(X_norm, 99, axis=0)

y_pred_if = (iso.predict(sc_if.transform(X_eval))==-1).astype(int)
print("\n=== Isolation Forest ===")
print(classification_report(y_eval, y_pred_if, target_names=['BENIGN','ATTACK']))
save_thresholds("iso", low_if, high_if)

# -------------------------------------------------
# 2‑B. One‑Class SVM (subsample + RBF)
# -------------------------------------------------
SUB = 60_000
idx = np.random.choice(X_train.shape[0], min(SUB, X_train.shape[0]), replace=False)
sc_svm = StandardScaler().fit(X_train[idx])
ocsvm  = OneClassSVM(kernel='rbf', nu=0.02, gamma='scale', cache_size=2048)\
           .fit(sc_svm.transform(X_train[idx]))

mask   = ocsvm.predict(sc_svm.transform(X_train)) == 1
X_norm = X_train[mask]
low_svm  = np.percentile(X_norm, 1 , axis=0)
high_svm = np.percentile(X_norm, 99, axis=0)

y_pred_svm = (ocsvm.predict(sc_svm.transform(X_eval))==-1).astype(int)
print("\n=== One‑Class SVM ===")
print(classification_report(y_eval, y_pred_svm, target_names=['BENIGN','ATTACK']))
save_thresholds("svm", low_svm, high_svm)

# -------------------------------------------------
# 2‑C. Gaussian Mixture 1‑D por feature
# -------------------------------------------------
low_gmm, high_gmm = [], []
for i,f in enumerate(FEATURES):
    Xf = X_train[:, i].reshape(-1,1)
    gmm = GaussianMixture(n_components=2, covariance_type='full',
                          random_state=42).fit(Xf)
    # get the main component (largest weight)
    main = np.argmax(gmm.weights_)
    mu   = gmm.means_[main,0]
    sd   = np.sqrt(gmm.covariances_[main,0,0])
    low_gmm.append(mu - 3*sd)
    high_gmm.append(mu + 3*sd)

gmm_pred = np.any((X_eval < low_gmm) | (X_eval > high_gmm), axis=1).astype(int)
print("\n=== Gaussian Mixture (1‑D, 3σ) ===")
print(classification_report(y_eval, gmm_pred, target_names=['BENIGN','ATTACK']))
save_thresholds("gmm", low_gmm, high_gmm)