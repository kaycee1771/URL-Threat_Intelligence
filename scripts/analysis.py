import psycopg2
import pandas as pd
from dotenv import load_dotenv
import os

# Database connection details
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

def export_detection_report():
    conn = psycopg2.connect(**DB_CONFIG)
    query = """
    SELECT u.url, u.threat_category, m.detection_method, m.detection_success, m.detection_time
    FROM scam_urls u
    JOIN detection_metrics m ON u.url_id = m.url_id;
    """
    data = pd.read_sql_query(query, conn)
    data.to_csv('C:/Users/kaytn/URL-Threat-Intelligence/reports/detection_report.csv', index=False)
    print("Report exported to C:/Users/kaytn/URL-Threat-Intelligence/reports/detection_report.csv")
    conn.close()

if __name__ == "__main__":
    export_detection_report()
