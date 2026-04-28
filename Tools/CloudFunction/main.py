"""
Google Cloud Function for EDR Telemetry Database Updates

This function handles webhook triggers to update the Supabase database
with the latest EDR telemetry data from GitHub.

Author: EDR Telemetry Project
"""

import os
import json
import logging
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from urllib.parse import quote

import requests
from supabase import create_client, Client
from flask import Request

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_GITHUB_REPOSITORY = "tsale/EDR-Telemetry"
DEFAULT_GITHUB_REF = "main"
WINDOWS_JSON_FILE = "EDR_telem_windows.json"
LINUX_JSON_FILE = "EDR_telem_linux.json"
MACOS_JSON_FILE = "EDR_telem_macOS.json"
MACOS_EXPLANATIONS_FILE = "partially_value_explanations_macOS.json"
LINUX_EXPLANATIONS_FILE = "partially_value_explanations_linux.json"
WINDOWS_EXPLANATIONS_FILE = "partially_value_explanations_windows.json"


def get_supabase_client() -> Client:
    """Initialize and return Supabase client"""
    url = os.environ.get('SUPABASE_URL')
    key = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')

    if not url or not key:
        raise ValueError("Missing Supabase configuration")

    return create_client(url, key)


def verify_webhook_signature(request: Request) -> bool:
    """Verify webhook signature for security"""
    webhook_secret = os.environ.get('WEBHOOK_SECRET')
    if not webhook_secret:
        allow_insecure = os.environ.get('WEBHOOK_ALLOW_INSECURE')
        if allow_insecure and allow_insecure.lower() == 'true':
            logger.warning("SECURITY WARNING: Webhook signature verification disabled via WEBHOOK_ALLOW_INSECURE override")
            return True

        logger.error("WEBHOOK_SECRET not configured and no insecure override present - failing webhook verification")
        return False

    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        logger.error("No signature provided in webhook")
        return False

    expected_signature = 'sha256=' + hmac.new(
        webhook_secret.encode('utf-8'),
        request.get_data(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)


def get_github_source(request: Request) -> Tuple[str, str]:
    """Return the repository and immutable ref to fetch telemetry data from."""
    payload = request.get_json(silent=True) or {}
    repository = payload.get('repository') or os.environ.get('GITHUB_REPOSITORY') or DEFAULT_GITHUB_REPOSITORY
    ref = payload.get('sha') or os.environ.get('GITHUB_REF') or DEFAULT_GITHUB_REF
    return repository, ref


def raw_github_url(repository: str, ref: str, path: str) -> str:
    """Build a GitHub raw content URL for the requested repository/ref/path."""
    safe_repository = "/".join(quote(part, safe='') for part in repository.split("/"))
    safe_ref = quote(ref, safe='')
    safe_path = "/".join(quote(part, safe='') for part in path.split("/"))
    return f"https://raw.githubusercontent.com/{safe_repository}/{safe_ref}/{safe_path}"


def fetch_json_data(url: str) -> List[Dict]:
    """Fetch JSON data from URL with error handling"""
    try:
        logger.info(f"Fetching data from {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching data from {url}: {str(e)}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON from {url}: {str(e)}")
        raise


def _update_platform_data(
    supabase: Client,
    telemetry_url: str,
    explanations_url: Optional[str],
    telemetry_table: str,
    results_table: str,
    platform_label: str,
) -> Dict[str, int]:
    """Generic platform data updater shared by Windows, Linux, and macOS."""
    logger.info(f"Starting {platform_label} data update")

    telemetry_data = fetch_json_data(telemetry_url)
    explanations_data = fetch_json_data(explanations_url) if explanations_url else []

    stats = {
        'categories_added': 0,
        'categories_updated': 0,
        'scores_added': 0,
        'scores_updated': 0,
        'errors': 0,
    }

    try:
        existing_categories = {}
        categories_response = supabase.table(telemetry_table).select('id,category,subcategory').execute()
        for cat in categories_response.data:
            existing_categories[f"{cat['category']}-{cat['subcategory']}"] = cat['id']

        last_category = ''

        for entry in telemetry_data:
            try:
                category = entry.get('Telemetry Feature Category') or last_category
                subcategory = entry.get('Sub-Category')

                if category:
                    last_category = category

                if not category or not subcategory:
                    logger.warning(f"Skipping entry with missing category/subcategory: {entry}")
                    continue

                category_key = f"{category}-{subcategory}"

                if category_key not in existing_categories:
                    cat_result = supabase.table(telemetry_table).insert({
                        'category': category,
                        'subcategory': subcategory,
                    }).execute()

                    if cat_result.data:
                        telemetry_id = cat_result.data[0]['id']
                        existing_categories[category_key] = telemetry_id
                        stats['categories_added'] += 1
                        logger.info(f"Added new {platform_label} category: {category}/{subcategory}")
                    else:
                        logger.error(f"Failed to insert {platform_label} category: {category}/{subcategory}")
                        stats['errors'] += 1
                        continue
                else:
                    telemetry_id = existing_categories[category_key]

                for edr_name, status in entry.items():
                    if edr_name in ['Telemetry Feature Category', 'Sub-Category'] or status is None:
                        continue

                    explanation = None
                    if status == 'Partially' and explanations_data:
                        explanation_entry = next(
                            (exp for exp in explanations_data
                             if exp.get('Telemetry Feature Category') == category
                             and exp.get('Sub-Category') == subcategory),
                            None,
                        )
                        if (explanation_entry and edr_name in explanation_entry
                                and isinstance(explanation_entry[edr_name], dict)
                                and 'Partially' in explanation_entry[edr_name]):
                            explanation = explanation_entry[edr_name]['Partially']

                    score_result = supabase.table(results_table).upsert({
                        'telemetry_id': telemetry_id,
                        'edr_name': edr_name,
                        'status': status,
                        'explanation': explanation,
                    }, on_conflict='telemetry_id,edr_name').execute()

                    if score_result.data:
                        stats['scores_updated'] += 1
                    else:
                        logger.error(f"Failed to upsert {platform_label} score for {edr_name}: {category}/{subcategory}")
                        stats['errors'] += 1

            except Exception as e:
                logger.error(f"Error processing {platform_label} entry {entry}: {str(e)}")
                stats['errors'] += 1
                continue

    except Exception as e:
        logger.error(f"Error in {platform_label} data update: {str(e)}")
        stats['errors'] += 1
        raise

    logger.info(f"{platform_label} update completed: {stats}")
    return stats


def update_windows_data(supabase: Client, repository: str, ref: str) -> Dict[str, int]:
    return _update_platform_data(
        supabase,
        telemetry_url=raw_github_url(repository, ref, WINDOWS_JSON_FILE),
        explanations_url=raw_github_url(repository, ref, WINDOWS_EXPLANATIONS_FILE),
        telemetry_table='windows_telemetry',
        results_table='windows_table_results',
        platform_label='Windows',
    )


def update_linux_data(supabase: Client, repository: str, ref: str) -> Dict[str, int]:
    return _update_platform_data(
        supabase,
        telemetry_url=raw_github_url(repository, ref, LINUX_JSON_FILE),
        explanations_url=raw_github_url(repository, ref, LINUX_EXPLANATIONS_FILE),
        telemetry_table='linux_telemetry',
        results_table='linux_table_results',
        platform_label='Linux',
    )


def update_macos_data(supabase: Client, repository: str, ref: str) -> Dict[str, int]:
    return _update_platform_data(
        supabase,
        telemetry_url=raw_github_url(repository, ref, MACOS_JSON_FILE),
        explanations_url=raw_github_url(repository, ref, MACOS_EXPLANATIONS_FILE),
        telemetry_table='macos_telemetry',
        results_table='macos_table_results',
        platform_label='macOS',
    )


def update_telemetry_data(request: Request) -> Tuple[Dict, int]:
    """
    Main function for Google Cloud Function

    Args:
        request: Flask request object

    Returns:
        Tuple of (response_dict, status_code)
    """
    start_time = datetime.now()

    try:
        if not verify_webhook_signature(request):
            return {'error': 'Invalid signature'}, 401

        platform = request.args.get('platform', 'all')
        logger.info(f"Processing update request for platform: {platform}")

        repository, ref = get_github_source(request)
        logger.info(f"Fetching telemetry data from {repository}@{ref}")

        supabase = get_supabase_client()

        results = {
            'timestamp': start_time.isoformat(),
            'platform': platform,
            'source_repository': repository,
            'source_ref': ref,
            'status': 'success',
            'windows_stats': None,
            'linux_stats': None,
            'macos_stats': None,
            'duration_seconds': None,
            'errors': [],
        }

        platform_jobs = {
            'windows': (update_windows_data, 'windows_stats'),
            'linux': (update_linux_data, 'linux_stats'),
            'macos': (update_macos_data, 'macos_stats'),
        }

        targets = platform_jobs.keys() if platform in ('all', 'both') else [platform]

        for target in targets:
            if target not in platform_jobs:
                logger.warning(f"Unknown platform requested: {target}")
                continue
            fn, key = platform_jobs[target]
            try:
                results[key] = fn(supabase, repository, ref)
            except Exception as e:
                error_msg = f"{target.capitalize()} update failed: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
                results['status'] = 'partial_failure'

        end_time = datetime.now()
        results['duration_seconds'] = (end_time - start_time).total_seconds()

        any_succeeded = any(results[k] is not None for k in ('windows_stats', 'linux_stats', 'macos_stats'))
        platform_error_count = sum(
            stats.get('errors', 0)
            for stats in (results['windows_stats'], results['linux_stats'], results['macos_stats'])
            if stats
        )
        if platform_error_count:
            results['errors'].append(f"Platform update errors encountered: {platform_error_count}")

        if results['errors']:
            results['status'] = 'partial_success' if any_succeeded else 'failure'
            status_code = 500
        else:
            results['status'] = 'success'
            status_code = 200

        logger.info(f"Update completed with status: {results['status']}")
        return results, status_code

    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        end_time = datetime.now()
        return {
            'timestamp': start_time.isoformat(),
            'status': 'failure',
            'error': error_msg,
            'duration_seconds': (end_time - start_time).total_seconds(),
        }, 500


def main(request: Request):
    """Cloud Function entry point"""
    response_data, status_code = update_telemetry_data(request)
    return response_data, status_code
