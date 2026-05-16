
import joblib
import pandas as pd
import numpy as np
import os
import json
import warnings
warnings.filterwarnings("ignore")

# Set BASE_DIR 
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "data", "models")

# --- Feature Definitions (from original project) ---
CATEGORICAL_COLS = ["sector", "size_category", "backup_frequency"]
BOOL_COLS = [
    "has_ciso", "uses_external_mssp", "has_siem", "has_threat_hunting",
    "has_ids_ips", "has_dlp", "has_edr", "has_drp", "backup_encryption",
    "has_soar", "dynamic_policy_updates", "has_devsecops",
    "cloud_security_posture", "continuous_improvement_program",
    "board_security_reporting", "bug_bounty_program",
]

# Model Loading#
def load_models():
    print("Loading CRASP models...")
    try:
        clf       = joblib.load(os.path.join(MODEL_DIR, "classifier.pkl"))
        scaler    = joblib.load(os.path.join(MODEL_DIR, "scaler_clf.pkl"))
        feat_cols = joblib.load(os.path.join(MODEL_DIR, "feature_cols.pkl"))
        regs      = {
            goal: joblib.load(os.path.join(MODEL_DIR, f"regressor_{goal}.pkl"))
            for goal in ["anticipate", "withstand", "recover", "adapt", "evolve"]
        }
        with open(os.path.join(MODEL_DIR, "model_metrics.json")) as f:
            metrics = json.load(f)
        print("Models loaded successfully.")
        return clf, scaler, feat_cols, regs, metrics
    except FileNotFoundError as e:
        print(f"Error loading model files: {e}")
        print(f"Please ensure the models are in the correct directory: {MODEL_DIR}")
        exit()

# Feature Preparation
def prepare_features_for_prediction(org_dict, feat_cols):
    df = pd.DataFrame([org_dict])
    for col in BOOL_COLS:
        if col in df.columns:
            df[col] = df[col].astype(int)
    df = pd.get_dummies(df, columns=[c for c in CATEGORICAL_COLS if c in df.columns])
    
    # Engineered features
    df["budget_per_employee"] = df.get("security_budget_usd", pd.Series([0])) / (df.get("employees", pd.Series([1])) + 1)
    df["staff_per_employee"]  = df.get("security_staff", pd.Series([0])) / (df.get("employees", pd.Series([1])) + 1) * 100
    df["tools_score"] = (
        df.get("has_siem", pd.Series([0])).astype(int) +
        df.get("has_soar", pd.Series([0])).astype(int) +
        df.get("has_ids_ips", pd.Series([0])).astype(int) +
        df.get("has_dlp", pd.Series([0])).astype(int) +
        df.get("has_edr", pd.Series([0])).astype(int)
    )
    df["detection_efficiency"] = 1 / (df.get("avg_detect_hours", pd.Series([48])) + 1)
    df["recovery_efficiency"]  = 1 / (df.get("avg_recovery_hours", pd.Series([72])) + 1)

    # Align all columns with training features, fill missing with 0
    for col in feat_cols:
        if col not in df.columns:
            df[col] = 0
    df = df[feat_cols]
    return df

# Scoring Logic #
def get_resilience_scores(org_data, clf, scaler, feat_cols, regs):
    processed_data = prepare_features_for_prediction(org_data, feat_cols)
    scaled_data = scaler.transform(processed_data)

    # Overall Resilience Level (Classification)
    resilience_level_idx = clf.predict(scaled_data)[0]
    resilience_level = resilience_level_idx + 1 # Adjust for 0-indexed labels
    
    # Individual Goal Scores (Regression)
    goal_scores = {}
    for goal_key, reg_model in regs.items():
        score = reg_model.predict(scaled_data)[0]
        # Ensure the score is a standard float and rounded for clean output
        goal_scores[goal_key.replace("regressor_", "")] = round(float(score), 1)

    # Calculate Overall Resilience Score (average of goal scores)
    overall_score = round(np.mean(list(goal_scores.values())), 1)

    return overall_score, resilience_level, goal_scores

# --- Default Organization Data --- #
default_org_data = {
    "sector": "Technology",
    "employees": 500,
    "revenue_million_usd": 100,
    "security_budget_pct": 0.05,
    "security_staff": 10,
    "has_ciso": True,
    "uses_external_mssp": False,
    "has_siem": True,
    "has_threat_hunting": True,
    "has_ids_ips": True,
    "has_dlp": False,
    "has_edr": True,
    "has_drp": True,
    "backup_encryption": True,
    "backup_frequency": "Daily",
    "threat_intel_feeds": 3,
    "vuln_scans_per_month": 4,
    "security_training_pct": 80,
    "avg_detect_hours": 24,
    "phishing_sim_per_year": 4,
    "firewall_layers": 3,
    "mfa_coverage_pct": 95,
    "encryption_at_rest_pct": 90,
    "encryption_in_transit_pct": 95,
    "patch_compliance_pct": 90,
    "network_segmentation_level": 3,
    "backup_tests_per_year": 2,
    "avg_recovery_hours": 48,
    "recovery_time_objective_hours": 72,
    "security_automation_pct": 60,
    "config_changes_per_year": 100,
    "post_incident_reviews_pct": 90,
    "security_metrics_tracked": 15,
    "security_certifications": 5,
    "incidents_last_year": 5,
    "successful_breaches": 1,
    "data_lost_gb": 10,
    "total_downtime_hours": 24,
    "has_soar": False,
    "dynamic_policy_updates": True,
    "has_devsecops": True,
    "cloud_security_posture": True,
    "continuous_improvement_program": True,
    "board_security_reporting": True,
    "bug_bounty_program": False,
}

# Main 
if __name__ == "__main__":
    print("\n" + "="*50)
    print("CRASP Lite: Cyber Resilience Assessment")
    print("="*50)

    clf, scaler, feat_cols, regs, metrics = load_models()

    print("\nAssessing default organization profile...")
    overall_score, resilience_level, goal_scores = get_resilience_scores(
        default_org_data, clf, scaler, feat_cols, regs
    )

    print("\n" + "-"*50)
    print("Assessment Results:")
    print("-"*50)
    print(f"Overall Resilience Score: {overall_score}/100")
    print(f"Resilience Level:         {resilience_level} (1=Critical, 5=Optimized)")
    print("\nResilience Goal Scores:")
    for goal, score in goal_scores.items():
        print(f"  - {goal.capitalize():<10}: {score}/100")
    print("-"*50)

    print("\nTo customize the assessment, edit the `default_org_data` dictionary in this script.")
    print("="*50)

