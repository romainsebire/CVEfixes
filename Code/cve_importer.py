import datetime
import time
import json
import os
import re
from io import BytesIO
import pandas as pd
import requests
from pathlib import Path
from zipfile import ZipFile
from pandas import json_normalize

from extract_cwe_record import add_cwe_class,  extract_cwe
import configuration as cf
import database as db

# ---------------------------------------------------------------------------------------------------------------------

df = pd.DataFrame()

ordered_cve_columns = ['cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
                       'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
                       'user_interaction_required',
                       'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
                       'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
                       'cvss2_base_score',
                       'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
                       'cvss3_privileges_required',
                       'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
                       'cvss3_integrity_impact',
                       'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
                       'exploitability_score', 'impact_score', 'ac_insuf_info',
                       'reference_json', 'problemtype_json']

cwe_columns = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

# ---------------------------------------------------------------------------------------------------------------------

def preprocess_jsons(df_in):
    """
    Flattening NVD API v2.0 JSON structures to match the legacy CVEfixes database schema.
    :param df_in: dataframe containing the raw 'cve' objects from v2.0 API
    """
    cf.logger.info('Flattening API v2.0 CVE items...')
    
    flattened_data = []
    
    for row in df_in['cve']:
        if not isinstance(row, dict):
            continue
            
        cve_id = row.get('id', '')
        published = row.get('published', '')
        last_modified = row.get('lastModified', '')
        
        description = ""
        for desc in row.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
                
        references = row.get('references', [])
        reference_json = json.dumps(references)
        
        weaknesses = row.get('weaknesses', [])
        problemtype_json = json.dumps(weaknesses)
        
        metrics = row.get('metrics', {})
        
        def get_metric(metric_key):
            m_list = metrics.get(metric_key, [])
            if m_list and isinstance(m_list, list) and len(m_list) > 0:
                return m_list[0]
            return {}
            
        v2_metric = get_metric('cvssMetricV2')
        v3_metric = get_metric('cvssMetricV31') or get_metric('cvssMetricV30')
        
        flat = {
            'cve_id': cve_id,
            'published_date': published,
            'last_modified_date': last_modified,
            'description': description,
            'nodes': '',
            'severity': v2_metric.get('baseSeverity', ''),
            
            'obtain_all_privilege': str(v2_metric.get('obtainAllPrivilege', '')),
            'obtain_user_privilege': str(v2_metric.get('obtainUserPrivilege', '')),
            'obtain_other_privilege': str(v2_metric.get('obtainOtherPrivilege', '')),
            'user_interaction_required': str(v2_metric.get('userInteractionRequired', '')),
            
            # CVSS V2
            'cvss2_vector_string': v2_metric.get('cvssData', {}).get('vectorString', ''),
            'cvss2_access_vector': v2_metric.get('cvssData', {}).get('accessVector', ''),
            'cvss2_access_complexity': v2_metric.get('cvssData', {}).get('accessComplexity', ''),
            'cvss2_authentication': v2_metric.get('cvssData', {}).get('authentication', ''),
            'cvss2_confidentiality_impact': v2_metric.get('cvssData', {}).get('confidentialityImpact', ''),
            'cvss2_integrity_impact': v2_metric.get('cvssData', {}).get('integrityImpact', ''),
            'cvss2_availability_impact': v2_metric.get('cvssData', {}).get('availabilityImpact', ''),
            'cvss2_base_score': str(v2_metric.get('cvssData', {}).get('baseScore', '')),
            
            # CVSS V3
            'cvss3_vector_string': v3_metric.get('cvssData', {}).get('vectorString', ''),
            'cvss3_attack_vector': v3_metric.get('cvssData', {}).get('attackVector', ''),
            'cvss3_attack_complexity': v3_metric.get('cvssData', {}).get('attackComplexity', ''),
            'cvss3_privileges_required': v3_metric.get('cvssData', {}).get('privilegesRequired', ''),
            'cvss3_user_interaction': v3_metric.get('cvssData', {}).get('userInteraction', ''),
            'cvss3_scope': v3_metric.get('cvssData', {}).get('scope', ''),
            'cvss3_confidentiality_impact': v3_metric.get('cvssData', {}).get('confidentialityImpact', ''),
            'cvss3_integrity_impact': v3_metric.get('cvssData', {}).get('integrityImpact', ''),
            'cvss3_availability_impact': v3_metric.get('cvssData', {}).get('availabilityImpact', ''),
            'cvss3_base_score': str(v3_metric.get('cvssData', {}).get('baseScore', '')),
            'cvss3_base_severity': v3_metric.get('cvssData', {}).get('baseSeverity', ''),
            
            'exploitability_score': str(v3_metric.get('exploitabilityScore', v2_metric.get('exploitabilityScore', ''))),
            'impact_score': str(v3_metric.get('impactScore', v2_metric.get('impactScore', ''))),
            'ac_insuf_info': str(v2_metric.get('acInsufInfo', '')),
            
            'reference_json': reference_json,
            'problemtype_json': problemtype_json
        }
        flattened_data.append(flat)
        
    df_cve = pd.DataFrame(flattened_data)
    
    # Check and add columns if they are not present in the dataframe
    for col in ordered_cve_columns:
        if col not in df_cve.columns:
            df_cve[col] = ""
            
    df_cve = df_cve[ordered_cve_columns]

    return df_cve


def assign_cwes_to_cves(df_cve: pd.DataFrame):
    df_cwes = extract_cwe()
    # fetching CWE associations to CVE records
    cf.logger.info('Adding CWE category to CVE records...')
    df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy()
    df_cwes_class['cwe_id'] = add_cwe_class(df_cwes_class['problemtype_json'].tolist())  # list of CWE-IDs' portion

    # exploding the multiple CWEs list of a CVE into multiple rows.
    df_cwes_class = df_cwes_class.assign(
        cwe_id=df_cwes_class.cwe_id).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')

    no_ref_cwes = set(list(df_cwes_class.cwe_id)).difference(set(list(df_cwes.cwe_id)))
    if len(no_ref_cwes) > 0:
        cf.logger.warning(f'Found {len(no_ref_cwes)} orphaned CWEs from NVD not present in the latest MITRE dictionary. Creating placeholders...')
        missing_cwes_list = []
        for missing_cwe in no_ref_cwes:
            missing_cwes_list.append({
                'cwe_id': missing_cwe,
                'cwe_name': 'Unknown/Deprecated NVD CWE',
                'description': 'This CWE ID was used by NVD but is not present in the latest MITRE XML dictionary.',
                'extended_description': '',
                'url': '',
                'is_category': False
            })
        df_cwes = pd.concat([df_cwes, pd.DataFrame(missing_cwes_list)], ignore_index=True)

    # Applying the assertion to cve-, cwe- and cwe_classification table.
    assert df_cwes.cwe_id.is_unique, "Primary keys are not unique in cwe records!"
    assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
        'Primary keys are not unique in cwe_classification records!'
    assert set(list(df_cwes_class.cwe_id)).issubset(set(list(df_cwes.cwe_id))), \
        'Not all foreign keys for the cwe_classification records are present in the cwe table!'

    df_cwes = df_cwes[cwe_columns].reset_index()  # to maintain the order of the columns
    df_cwes.to_sql(name="cwe", con=db.conn, if_exists='replace', index=False)
    df_cwes_class.to_sql(name='cwe_classification', con=db.conn, if_exists='replace', index=False)
    cf.logger.info('Added cwe and cwe_classification tables')


def import_cves():
    """
    Gathering CVE records by processing JSON data directly from NVD API 2.0.
    Uses pagination and defensive pacing to avoid API rate limits without a key.
    """

    cf.logger.info('-' * 70)
    if db.table_exists('cve'):
        cf.logger.warning('The cve table already exists, but we are overwriting it from scratch...')

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page = 2000
    all_cves_raw = []

    DEBUG_MODE = False 
    MAX_TEST_CVES = 4000
    try:
        cf.logger.info("Fetching initial metadata from NVD...")
        response = requests.get(f"{base_url}?resultsPerPage=1", timeout=30)
        if response.status_code != 200:
            cf.logger.error("Failed to connect to NVD API.")
            return
        
        data = response.json()
        total_results = data.get("totalResults", 0)
    except Exception as e:
        cf.logger.error(f"Error during initial connection: {e}")
        return
    
    if DEBUG_MODE:
        start_index = max(0, total_results - MAX_TEST_CVES)
        cf.logger.info(f"[DEBUG MODE] Fetching last {MAX_TEST_CVES} CVEs (starting at {start_index}).")
    else:
        start_index = 0
        cf.logger.info(f"Fetching all {total_results} CVEs.")
    cf.logger.info('Starting NVD API v2.0 download (without API key)...')

    while start_index < total_results:
        url = f"{base_url}?startIndex={start_index}&resultsPerPage={results_per_page}"
        cf.logger.info(f"Fetching {min(start_index + results_per_page, total_results)} / {total_results}...")

        try:
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                
                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    cf.logger.info(f"Total CVEs to download: {total_results}")

                vulns = data.get("vulnerabilities", [])
                all_cves_raw.extend(vulns)

                start_index += results_per_page
                cf.logger.info(f"Progress: {min(start_index, total_results)} / {total_results} CVEs downloaded.")

                time.sleep(6) # 5 req/30s

            elif response.status_code in [403, 429, 503]:
                cf.logger.warning(f"NVD API rate limit or server error (Code {response.status_code}). Sleeping 15s...")
                time.sleep(15)
            else:
                cf.logger.error(f"Unexpected HTTP error {response.status_code}. Sleeping 15s...")
                time.sleep(15)

        except requests.exceptions.RequestException as e:
            cf.logger.warning(f"Network error: {e}. Sleeping 15s before retrying...")
            time.sleep(15)

    cf.logger.info("Download complete. Creating DataFrame...")
    
    df_cve = pd.DataFrame(all_cves_raw)

    cf.logger.info("Preprocessing the JSON structures...")
    df_cve = preprocess_jsons(df_cve)
    df_cve = df_cve.map(str)
    
    assert df_cve.cve_id.is_unique, 'Primary keys are not unique in cve records!'
    
    cf.logger.info("Saving to SQLite database...")
    df_cve.to_sql(name="cve", con=db.conn, if_exists="replace", index=False)
    
    cf.logger.info('All CVEs have been merged into the cve table')
    cf.logger.info('-' * 70)

    assign_cwes_to_cves(df_cve=df_cve)
