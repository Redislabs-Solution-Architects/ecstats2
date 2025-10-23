#!/usr/bin/env python3
"""
ECstats Enhancement Script

Adds instance specifications to ECstats output:
- MemoryGB, vCPUs, NetworkPerf (from Vantage API)
- AvgKeySize (calculated from existing data)

Usage:
    python enhance_stats.py -i production-us-east-1.xlsx

API Token:
    Create a .env file in the project root with:
    VANTAGE_API_TOKEN=your_token_here

    Get your free token at: https://console.vantage.sh
"""

import os
import sys
import argparse
import openpyxl
import requests
from typing import Tuple, Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Cache for instance specs to avoid repeated API calls
INSTANCE_SPECS_CACHE = {}


def get_vantage_api_token():
    """Get the Vantage API token from .env file."""
    token = os.environ.get("VANTAGE_API_TOKEN")
    if not token:
        print("ERROR: VANTAGE_API_TOKEN not found in environment")
        print("\nPlease create a .env file in the project root with:")
        print("VANTAGE_API_TOKEN=your_token_here")
        print("\nGet your free token at: https://console.vantage.sh")
        sys.exit(1)
    return token


def get_instance_specs_from_vantage(
    instance_type: str, api_token: str, verbose: bool = False
) -> Tuple[Optional[float], Optional[int], Optional[str]]:
    """
    Get instance specifications from Vantage API.

    Args:
        instance_type: ElastiCache instance type (e.g., cache.r6g.xlarge)
        api_token: Vantage API token

    Returns:
        Tuple of (memory_gb, vcpus, network_performance) or (None, None, None) if not found
    """
    # Check cache first
    if instance_type in INSTANCE_SPECS_CACHE:
        return INSTANCE_SPECS_CACHE[instance_type]

    # ElastiCache instances map to EC2 instance types (remove 'cache.' prefix)
    ec2_instance_type = instance_type.replace("cache.", "")

    try:
        # Query Vantage API for the instance type
        # ElastiCache uses EC2 instance types, so we query the EC2 service
        headers = {"Authorization": f"Bearer {api_token}"}
        url = "https://api.vantage.sh/v1/products"
        params = {
            "provider_id": "aws",
            "service_id": "aws-ec2",
        }

        print(f"  Fetching specs for {instance_type} from Vantage API...")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()

        products = response.json()
        print(f"  Vantage API returned {len(products.get('products', []))} products")

        # Debug: print full response if verbose
        if verbose:
            import json
            print("\n=== FULL VANTAGE API RESPONSE ===")
            print(json.dumps(products, indent=2))
            print("=== END RESPONSE ===\n")

        # Find the matching instance type by name field
        for product in products.get("products", []):
            product_name = product.get("name", "")
            if product_name == ec2_instance_type:
                # Try to extract specs from details first, then from top level
                details = product.get("details", {})
                memory_gb = details.get("memory") or product.get("memory")
                vcpus = details.get("vcpu") or product.get("vcpu")
                network_perf = (
                    details.get("network_performance_description")
                    or product.get("network_performance_description")
                    or "Unknown"
                )

                if verbose:
                    print(f"\n  Full product object for {instance_type}:")
                    import json
                    print(json.dumps(product, indent=2))

                print(f"  ✓ Found {instance_type}: {memory_gb}GB RAM, {vcpus} vCPUs, {network_perf}")
                result = (memory_gb, vcpus, network_perf)
                INSTANCE_SPECS_CACHE[instance_type] = result
                return result

        # Not found in API, return None
        print(f"  ✗ {instance_type} not found in Vantage API response")
        print(f"  Looking for EC2 instance type: {ec2_instance_type}")
        INSTANCE_SPECS_CACHE[instance_type] = (None, None, None)
        return (None, None, None)

    except Exception as e:
        print(f"  ✗ API Error for {instance_type}: {e}")
        INSTANCE_SPECS_CACHE[instance_type] = (None, None, None)
        return (None, None, None)


def enhance_ecstats_output(input_file: str, output_file: str, verbose: bool = False):
    """
    Enhance ECstats output with additional columns.

    Args:
        input_file: Path to original ECstats Excel output
        output_file: Path to save enhanced output
    """
    api_token = get_vantage_api_token()

    print(f"Loading workbook: {input_file}")
    wb = openpyxl.load_workbook(input_file)

    # Process ClusterData sheet
    if "ClusterData" not in wb.sheetnames:
        print("ERROR: ClusterData sheet not found in workbook")
        sys.exit(1)

    ws = wb["ClusterData"]

    # Find header row
    header_row = list(ws.iter_rows(min_row=1, max_row=1, values_only=True))[0]
    header_list = list(header_row)

    # Find key column indices
    node_type_col = header_list.index("NodeType") if "NodeType" in header_list else None
    curr_items_col = (
        header_list.index("CurrItems") if "CurrItems" in header_list else None
    )
    bytes_used_col = (
        header_list.index("BytesUsedForCache")
        if "BytesUsedForCache" in header_list
        else None
    )

    if node_type_col is None:
        print("ERROR: NodeType column not found")
        sys.exit(1)

    # Add new column headers (before Engine column)
    new_headers = ["MemoryGB", "vCPUs", "NetworkPerf", "AvgKeySize"]

    engine_col = (
        header_list.index("Engine") if "Engine" in header_list else len(header_list)
    )

    for idx, new_header in enumerate(new_headers):
        ws.cell(row=1, column=engine_col + idx + 1, value=new_header)

    # Process each data row
    print("Enhancing rows with instance specs...")
    for row_idx in range(2, ws.max_row + 1):
        if row_idx % 10 == 0:
            print(f"  Processing row {row_idx}/{ws.max_row}")

        node_type = ws.cell(row=row_idx, column=node_type_col + 1).value

        # Get instance specs from Vantage API
        if node_type:
            memory_gb, vcpus, network_perf = get_instance_specs_from_vantage(
                node_type, api_token, verbose
            )

            ws.cell(row=row_idx, column=engine_col + 1, value=memory_gb or "Unknown")
            ws.cell(row=row_idx, column=engine_col + 2, value=vcpus or "Unknown")
            ws.cell(row=row_idx, column=engine_col + 3, value=network_perf or "Unknown")

        # Calculate AvgKeySize
        if bytes_used_col and curr_items_col:
            bytes_used = ws.cell(row=row_idx, column=bytes_used_col + 1).value
            curr_items = ws.cell(row=row_idx, column=curr_items_col + 1).value

            if bytes_used and curr_items and curr_items > 0:
                avg_key_size = round(bytes_used / curr_items)
                ws.cell(row=row_idx, column=engine_col + 4, value=avg_key_size)

    # Save enhanced workbook
    print(f"Saving enhanced workbook: {output_file}")
    wb.save(output_file)
    print("Done!")


def main():
    parser = argparse.ArgumentParser(
        description="Enhance ECstats output with instance specs"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input Excel file from ecstats.py",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output Excel file (default: {input}-enhanced.xlsx)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print full Vantage API response for debugging",
    )

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: Input file not found: {args.input}")
        sys.exit(1)

    # Determine output file
    if args.output:
        output_file = args.output
    else:
        base_name = os.path.splitext(args.input)[0]
        output_file = f"{base_name}-enhanced.xlsx"
        print(f"Output will be saved to: {output_file}")

    enhance_ecstats_output(args.input, output_file, args.verbose)


if __name__ == "__main__":
    main()
