# CRASP Lite: Terminal-Based Cyber Resilience Assessment

This is a simplified, terminal-based version of the Cyber Resilience Assessment and Scoring Platform (CRASP) designed for quick assessments and demonstrations. It focuses solely on calculating an organization's overall resilience score and individual scores across the five key dimensions (Anticipate, Withstand, Recover, Adapt, Evolve), without the web dashboard or future prediction features.

## 🚀 Getting Started

To run CRASP Lite on your local machine, follow these steps:

1.  **Prerequisites:** Ensure you have Python 3.9+ installed.

2.  **Install Dependencies:**
    Navigate to the `crasp_lite` directory in your terminal and install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Assessment:**
    Execute the main script:
    ```bash
    python crasp_lite.py
    ```
    This will run an assessment using a default organization profile and print the results directly to your terminal.

## ⚙️ Customizing the Assessment

The `crasp_lite.py` script contains a `default_org_data` dictionary. You can modify this dictionary to assess different organizational profiles. Change the values for `sector`, `employees`, `has_siem`, `security_budget_pct`, and other parameters to see how they impact the resilience scores.

## 📂 Project Structure

```
crasp_lite/
├── crasp_lite.py           # Main script for terminal-based assessment
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── data/
    └── models/             # Pre-trained ML models (copied from the full CRASP project)
        ├── classifier.pkl
        ├── scaler_clf.pkl
        ├── feature_cols.pkl
        ├── regressor_anticipate.pkl
        ├── regressor_withstand.pkl
        ├── regressor_recover.pkl
        ├── regressor_adapt.pkl
        ├── regressor_evolve.pkl
        └── model_metrics.json
```

## ✨ Features

*   **Overall Resilience Score:** A single metric (0-100) indicating the organization's cyber resilience.
*   **5-Dimension Scoring:** Detailed scores for Anticipate, Withstand, Recover, Adapt, and Evolve.
*   **Terminal Output:** Clean, easy-to-read results directly in your command line.
*   **Customizable Input:** Easily modify the organization's profile within the script to perform various case studies.

This simplified version is ideal for academic presentations, quick analyses, or integrating the core scoring logic into other applications.
