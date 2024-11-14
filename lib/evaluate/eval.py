
import pandas as pd

def filter_df(df, start_date, end_date, resample):
    _df = df.loc[(df.index >= pd.Timestamp(str(start_date))) & (df.index < pd.Timestamp(str(end_date)))]
    return _df.resample(resample).sum()

def get_usage_estimation(pv_df, sm_df, estimation_threshold=0.000, basic_energy_usage=0.01):
    start_date = '2023-09-04'
    end_date = '2199-01-01'
    resample = '15min'
    filtered_pv_df = filter_df(pv_df, start_date, end_date, resample)
    filtered_sm_df = filter_df(sm_df, start_date, end_date, resample)

    df = pd.concat([filtered_pv_df, filtered_sm_df], axis=1)
    df.columns = ['pv', 'sm']
    df.fillna({'pv': 0}, inplace=True)

    def estimate_energy_usage(row):
        pv = row['pv']
        sm = row['sm']
        if (sm > estimation_threshold):
            return pv
        return min(basic_energy_usage, pv)
    df['est_usage'] = df.apply(estimate_energy_usage, axis=1)
    df['est_total'] = df['sm'] + df['est_usage']
    return (df['est_usage'], df['est_total'])

