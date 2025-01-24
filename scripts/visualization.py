import psycopg2
import pandas as pd
import matplotlib.pyplot as plt
from dotenv import load_dotenv
import os

load_dotenv()

# Database connection details
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

# Connect to the database
conn = psycopg2.connect(**DB_CONFIG)

# Query to get threat categories count
query = """
SELECT threat_category, COUNT(*) AS count
FROM scam_urls
GROUP BY threat_category
ORDER BY count DESC;
"""
data = pd.read_sql_query(query, conn)

# Plot the data
plt.bar(data['threat_category'], data['count'])
plt.xlabel('Threat Category')
plt.ylabel('Count')
plt.title('Threat Categories Distribution')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Close the database connection
conn.close()
