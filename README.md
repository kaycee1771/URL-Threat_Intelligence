# URL Threat Intelligence System

## Overview
The URL Threat Intelligence System is a Python-based project designed to identify, classify, and manage potentially malicious URLs. It provides a robust platform for storing and analyzing URLs by assessing their risk levels and threat categories. This system enables cybersecurity professionals and researchers to detect malicious patterns, assign severity levels, and track trends in online threats.

## Features
### Current Features
1. **User-Friendly Interface**
   - Allows users to input URLs directly via a prompt.
   - Supports category and source selection with predefined options or user-defined entries.

2. **Threat Classification**
   - Assigns threat categories (e.g., phishing, malware, ransomware) to URLs.
   - Includes a severity scoring system based on URL characteristics.

3. **Risk Analysis**
   - Extracts URL features like domain, TLD (Top-Level Domain), and length.
   - Calculates a risk score for each URL.

4. **Database Management**
   - Stores URLs and their metadata in a PostgreSQL database.
   - Avoids duplicate entries with efficient conflict resolution.

5. **Data Analysis**
   - Provides analysis of stored data using SQL and Python.
   - Includes features like:
     - Generating reports on threat categories and detection metrics.
     - Exporting detection data to CSV for further analysis.

6. **Data Visualization**
   - Visualizes threat category distribution and other insights using Matplotlib.
   - Enables users to better understand trends and patterns in malicious URLs.

7. **Extensible Framework**
   - Designed to integrate with live threat feeds and machine learning models.

## Installation

### Prerequisites
1. **Python**: Ensure Python 3.8 or higher is installed.
2. **PostgreSQL**: Install and configure a PostgreSQL database.
3. **Dependencies**: Install required Python packages using the `requirements.txt` file.

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/URL-Threat-Intelligence.git
   cd URL-Threat-Intelligence
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the database:
   - Use the SQL schema file to create the necessary tables:
     ```bash
     psql -U postgres -d threat_db -f sql/schema.sql
     ```

4. Configure environment variables:
   - Create a `.env` file to store sensitive information:
     ```env
     DB_NAME=threat_db
     DB_USER=postgres
     DB_PASSWORD=your_database_password
     DB_HOST=localhost
     DB_PORT=5432
     ```

5. Run the application:
   ```bash
   python data_ingestion.py
   ```

## Usage

1. **Add a New URL**
   - The system prompts you to enter a URL, select its category, and specify its source.
   - Automatically calculates the risk score and assigns a severity level.

2. **Data Storage and Analysis**
   - All inputs are stored in the database for further analysis.
   - The system avoids duplicate entries and updates existing records when necessary.

3. **Analysis and Visualization**
   - Run the `analysis.py` script to:
     - Generate CSV reports on detection metrics and threat categories.
     - Export detection data for external use.
   - Run the `visualization.py` script to:
     - Generate visual insight into threat category distribution.

   Example to generate a CSV report:
   ```bash
   python analysis.py
   ```

   Example of visualizing threat category distribution:
   ```bash
   python visualization.py
   ```

## Planned Updates (Long-Term Goals)

### 1. **Advanced Analytics**
   - Analyze malicious URL patterns (e.g., common domains, keywords, and TLDs).
   - Introduce similarity analysis to detect phishing URLs mimicking legitimate sites.

### 2. **Integration with Live Threat Feeds**
   - Integrate with APIs from sources like URLHaus to fetch real-time threat intelligence.
   - Data from these feeds are automatically ingested into the system.

### 3. **Machine Learning Integration**
   - Develop and deploy a machine learning model to predict the risk level of URLs based on features.
   - Use historical data to train the model for classification and anomaly detection.

### 4. **Web-Based Dashboard**
   - Create a user-friendly web interface using Flask or Django.
   - Features:
     - Search for URLs and view their details.
     - Visualize trends with interactive charts.
     - Upload bulk URL data for analysis.

### 5. **Automated Reporting**
   - Generate periodic reports summarizing key metrics:
     - Top threat categories.
     - Most frequently flagged domains.
     - Detection success rates.
   - Send reports via email to administrators.

### 6. **Real-Time Monitoring**
   - Implement real-time monitoring to flag high-risk URLs as they are entered.
   - Introduce an option to monitor live web traffic logs for threats.

### 7. **User Feedback Loop**
   - Allow users to flag URLs as false positives or confirm malicious entries.
   - Use this feedback to refine detection models and rules.

### 8. **Scalability Enhancements**
   - Migrate to a cloud platform (e.g., AWS, Google Cloud) for scalability and availability.
   - Optimize database performance with indexing and sharding techniques.

## Contribution

Contact: kelechi.okpala13@yahoo.com

## License
This project is licensed under the MIT License

## Acknowledgments
- **PostgreSQL** for reliable database management.
- The open-source community for their contributions and support.

---
Feel free to reach out for suggestions or collaboration!

