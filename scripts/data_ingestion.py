import psycopg2
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv
import os
import requests
import re
from ml_training import load_model, predict_url

load_dotenv()

# Database connection details
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

# Function to connect to the database
def connect_to_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print("Connected to the database successfully.")
        return conn
    except Exception as e:
        print("Error connecting to the database:", e)
        return None

# Function to validate a URL
def is_valid_url(url):
    """Validate a URL and handle missing schemes."""
    url = url.strip() 
    if not url.startswith(("http://", "https://")):
        url = "http://" + url 

    parsed = urlparse(url)


    if not parsed.netloc or not parsed.scheme:
        return False

    regex = re.compile(
        r'^(http|https)://'  
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})' 
        r'(:[0-9]{1,5})?'  
        r'(\/.*)?$'  
    )
    return re.match(regex, url) is not None

# Function to insert a new URL into scam_urls
def insert_scam_url(cursor, url, category, source):
    query = """
    INSERT INTO scam_urls (url, threat_category, source)
    VALUES (%s, %s, %s)
    ON CONFLICT (url) DO NOTHING
    RETURNING url_id;
    """
    cursor.execute(query, (url, category, source))
    result = cursor.fetchone()
    return result[0] if result else None

# Function to extract features from a URL
def extract_url_features(url):
    parsed = urlparse(url.strip().lower())
    domain = parsed.netloc
    tld = domain.split('.')[-1] if '.' in domain else None
    url_length = len(url)
    return domain, tld, url_length

# Function to assign severity based on threat category
def assign_severity(category):
    if category == "phishing":
        return "medium"
    elif category == "malware":
        return "high"
    elif category == "ransomware":
        return "critical"
    else:
        return "low"

# Function to calculate a risk score for a URL
def calculate_score(category, url_length, tld):
    score = 0
    if category == "phishing":
        score += 50
    if url_length > 50:
        score += 10
    if tld in ["xyz", "tk", "ml"]:
        score += 20
    return score

# Fetch data from URLHaus
def fetch_urlhaus_data():
    url = "https://urlhaus.abuse.ch/downloads/csv/"
    response = requests.get(url)
    if response.status_code == 200:
        print("Fetched URLHaus data successfully!")
        return response.text.splitlines()
    else:
        print(f"Failed to fetch URLHaus data. Status code: {response.status_code}")
        return []

# Clean data fetched from URLHaus
def clean_data(line):
    try:
        line = line.replace('\x00', '')
        fields = line.split(",")
        if len(fields) > 2 and fields[2].startswith("http"):
            return fields[2]
    except Exception as e:
        print(f"Error processing line: {line} - {e}")
    return None

# Ingest cleaned URLHaus data
def ingest_urlhaus_data(data, cursor):
    for line in data[9:]:  
        url = clean_data(line)
        if url and is_valid_url(url):
            category = "malware"
            source = "URLHaus"
            try:
                url_id = insert_scam_url(cursor, url, category, source)
                if url_id:
                    print(f"Ingested URL: {url}")
                else:
                    print(f"Skipped duplicate URL: {url}")
            except Exception as e:
                print(f"Error inserting URL: {url} - {e}")
        else:
            print(f"Invalid or corrupted URL skipped: {line}")

# Load the trained ML model
ml_model = load_model("ml_model.pkl")
    
# Function to display category options
def display_category_options():
    print("\nSelect a threat category:")
    print("1. Phishing")
    print("2. Malware")
    print("3. Ransomware")
    print("4. Other")

    while True:
        category_choice = input("Enter the option number for the category: ")
        if category_choice == "1":
            return "phishing"
        elif category_choice == "2":
            return "malware"
        elif category_choice == "3":
            return "ransomware"
        elif category_choice == "4":
            return input("Please specify the threat category: ").strip().lower()
        else:
            print("Invalid choice. Please select a valid option.")

# Function to display source options
def display_source_options():
    print("\nSelect the source of the URL:")
    print("1. User")
    print("2. External Feed")
    print("3. Other")

    while True:
        source_choice = input("Enter the option number for the source: ")
        if source_choice == "1":
            return "user"
        elif source_choice == "2":
            return "external feed"
        elif source_choice == "3":
            return input("Please specify the source: ").strip().lower()
        else:
            print("Invalid choice. Please select a valid option.")

# Main function to prompt the user
def prompt_user():
    conn = connect_to_db()
    if not conn:
        return
    cursor = conn.cursor()

    while True:
        print("\nChoose an action:")
        print("1. Add a new URL")
        print("2. Fetch data from URLHaus")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            # User inputs the URL
            url = input("Enter the URL: ")

            if not is_valid_url(url):
                print("Invalid URL. Please try again.")
                continue
        
            # Classify URL using the trained ML model
            if ml_model:
                classification = predict_url(url, ml_model)
                print(f"The URL is classified as: {classification}")

            # Get category and source
            category = display_category_options()
            source = display_source_options()

            # Extract features and insert the URL
            domain, tld, url_length = extract_url_features(url)
            severity = assign_severity(category)
            score = calculate_score(category, url_length, tld)

            url_id = insert_scam_url(cursor, url, category, source)
            if url_id:
                cursor.execute(
                    """
                    UPDATE scam_urls
                    SET domain = %s, tld = %s, url_length = %s, severity = %s, score = %s
                    WHERE url_id = %s;
                    """,
                    (domain, tld, url_length, severity, score, url_id)
                )
                print(f"URL successfully added with ID: {url_id}")
            else:
                print("The URL already exists in the database or was invalid.")

            conn.commit()

        elif choice == "2":
            urlhaus_data = fetch_urlhaus_data()
            if urlhaus_data:
                ingest_urlhaus_data(urlhaus_data, cursor)
                conn.commit()
                print("URLHaus data ingestion completed.")

        elif choice == "3":
            print("Exiting. Goodbye!")
            break

        else:
            print("Invalid choice. Please select a valid option.")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    prompt_user()
