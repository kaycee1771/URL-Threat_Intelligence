import os
import pandas as pd
from sqlalchemy import create_engine
from difflib import SequenceMatcher
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# Validate environment variables
if not all([DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT]):
    raise ValueError("One or more required environment variables are missing. Check your .env file.")

# Create SQLAlchemy engine
try:
    engine = create_engine(
        f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    print("Database engine created successfully.")
except Exception as e:
    print(f"Error creating database engine: {e}")
    raise

# Ensure the reports directory exists
def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Analyze TLD distribution
def analyze_tld_distribution():
    query = """
    SELECT tld, COUNT(*) AS count
    FROM scam_urls
    GROUP BY tld
    ORDER BY count DESC;
    """
    data = pd.read_sql_query(query, engine)
    print("TLD Distribution:")
    print(data)

# Export detection report
def export_detection_report():
    query = """
    SELECT u.url, u.threat_category, m.detection_method, m.detection_success, m.detection_time
    FROM scam_urls u
    JOIN detection_metrics m ON u.url_id = m.url_id;
    """
    data = pd.read_sql_query(query, engine)
    ensure_directory_exists("C:/Users/kaytn/URL-Threat-Intelligence/reports")
    report_path = "C:/Users/kaytn/URL-Threat-Intelligence/reports/detection_report.csv"
    data.to_csv(report_path, index=False)
    print(f"Report exported to {report_path}")

# URL similarity ratio
def similarity_ratio(url1, url2):
    return SequenceMatcher(None, url1, url2).ratio()

if __name__ == "__main__":
    try:
        print("\nAnalyzing TLD Distribution...")
        analyze_tld_distribution()

        print("\nExporting Detection Report...")
        export_detection_report()

        print("\nTesting URL Similarity:")
        url1 = "paycom.ru"
        url2 = "payme.se"
        print(f"Similarity between '{url1}' and '{url2}': {similarity_ratio(url1, url2):.2f}")
    except Exception as e:
        print(f"Error: {e}")
