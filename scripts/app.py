from flask import Flask, render_template, request  
import psycopg2  
import os  
from dotenv import load_dotenv  

# Initialize Flask application 
app = Flask(__name__, template_folder="C:/Users/kaytn/URL-Threat-Intelligence/templates")


load_dotenv()

# Database connection details, loaded from environment variables
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),  
    "user": os.getenv("DB_USER"),  
    "password": os.getenv("DB_PASSWORD"),  
    "host": os.getenv("DB_HOST"),  
    "port": os.getenv("DB_PORT")  
}

# Route for the home page
@app.route('/')
def home():
    return render_template("index.html")

# Route to add a URL to the database
@app.route('/add_url', methods=["POST"])
def add_url():
    url = request.form["url"]  
    category = request.form["category"]  
    source = request.form["source"]  

    # Connect to the database
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Insert the URL into the database, ignoring duplicates
    cursor.execute("""
        INSERT INTO scam_urls (url, threat_category, source)
        VALUES (%s, %s, %s) ON CONFLICT (url) DO NOTHING;
    """, (url, category, source))

    conn.commit()  
    cursor.close()  
    conn.close()  
    return "URL added successfully!"  

# Route to fetch and display high-risk URLs
@app.route('/high_risk')
def high_risk():
    # Connect to the database
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Select high-risk URLs based on severity or score
    cursor.execute("SELECT url, severity, score FROM scam_urls WHERE severity = 'critical' OR score > 70;")
    data = cursor.fetchall()  

    cursor.close()  
    conn.close()  

    return render_template("high_risk.html", data=data)

# Route to handle feedback submission for URLs
@app.route('/feedback', methods=["POST"])
def feedback():
    url_id = request.form["url_id"] 
    feedback = request.form["feedback"] 

    # Connect to the database
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute("UPDATE scam_urls SET feedback = %s WHERE url_id = %s;", (feedback, url_id))

    conn.commit() 
    cursor.close() 
    conn.close()  

    return "Feedback submitted!" 

if __name__ == "__main__":
    app.run(debug=True)
