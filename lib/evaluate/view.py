
import matplotlib.pyplot as plt
from datetime import timedelta, datetime
import numpy as np

def initialize_figure():
    fig, ax = plt.subplots(constrained_layout=True, figsize=(16, 8))
    fig.canvas.toolbar_visible = False
    fig.canvas.header_visible = False
    fig.canvas.footer_visible = False
    fig.canvas.resizable = False
    return fig, ax

def get_details_table(data, pv_title, sm_title, est_usage_title, est_total_title):
    def get_cell(value, unit, bold):
        if value == None:
            return ''
        ret = f'{value:.3f}{unit}'
        if bold:
            return f'<b>{ret}</b>'
        else:
            return ret
    def get_row(d): 
        c1 = get_cell(d[3], d[1], d[2])
        c2 = get_cell(d[4], d[1], d[2])
        c3 = get_cell(d[5], d[1], d[2])
        c4 = get_cell(d[6], d[1], d[2])
        return f"""
        <tr>
            <th><b>{d[0]}</b></th>
            <td>{c1}</td>
            <td>{c2}</td>
            <td>{c3}</td>
            <td>{c4}</td>
        </tr>
        """
    rows = map(get_row, data)
    return f"""
        <table>
            <tr>
                <th></th>
                <th><b>{pv_title}</b></th>
                <th><b>{sm_title}</b></th>
                <th><b>{est_usage_title}</b></th>
                <th><b>{est_total_title}</b></th>
            </tr>
            {''.join(rows)}
        </table>
        """

def print_df_details(output_detail, pv_df, sm_df, est_usage_df, est_total_df, pv_title, sm_title, est_usage_title, est_total_title):
    def to_percent(dividend, divisor):
        if divisor == 0:
            return 0
        return dividend / divisor * 100
    details = [
        ('Sum', ' kWh', False, pv_df.sum(), sm_df.sum(), est_usage_df.sum(), est_total_df.sum()),
        ('Median', ' kWh', False, pv_df.median(), sm_df.median(), est_usage_df.median(), est_total_df.median()),
        ('Mean', ' kWh', False, pv_df.mean(), sm_df.mean(), est_usage_df.mean(), est_total_df.mean()),
        ('Standard Deviation', ' kWh', False, pv_df.std(), sm_df.std(), est_usage_df.std(), est_total_df.std()),
        ('Minimum', ' kWh', False, pv_df.min(), sm_df.min(), est_usage_df.min(), est_total_df.min()),
        ('Maximum', ' kWh', False, pv_df.max(), sm_df.max(), est_usage_df.max(), est_total_df.max()),
        ('Efficiency', '%', True, None, None, to_percent(est_usage_df.sum(), pv_df.sum()), to_percent(est_usage_df.sum(), est_total_df.sum())),
        ('Potential', '%', True, None, None, None, to_percent(pv_df.sum(), est_total_df.sum())),
    ]
    output_detail.value = get_details_table(details, pv_title, sm_title, est_usage_title, est_total_title)

def draw_weekend_background(df):
    if (len(df.index) <= 0):
        return
    timespan = max(df.index) - min(df.index)
    if timespan < timedelta(days=6) or timespan > timedelta(days=25):
        return
    
    dates = np.unique(df.index.date)
    weekend_days = list(filter(lambda d: d.weekday() >= 5, dates))
    weekend_days_with_time = list(map(lambda d: datetime.combine(d, datetime.min.time()), weekend_days))
    for day in weekend_days_with_time:
        plt.axvspan(day-timedelta(hours=12), day+timedelta(hours=12), facecolor='0.8', alpha=0.9)

def draw_df(ax, pv_df, sm_df, est_usage_df, est_total_df, show_pv, show_sm, show_est_usage, show_est_total, pv_title, sm_title, est_usage_title, est_total_title):
    ax.clear()
    ax.autoscale()
    ax.set_xlabel('Timestamp')
    ax.set_ylabel('Energy [kWh]')
    ax.grid(True)
    if show_pv:
        ax.plot(pv_df, color='C0', marker='o', label=pv_title)
    if show_sm:
        ax.plot(sm_df, color='C3', marker='o', label=sm_title)
    if show_est_usage:
        ax.plot(est_usage_df, color='C2', marker='o', label=est_usage_title)
    if show_est_total:
        ax.plot(est_total_df, color='C7', marker='o', label=est_total_title)
    draw_weekend_background(pv_df)
    ax.legend()
    ax.set_ylim(bottom=0.0, auto=True)
