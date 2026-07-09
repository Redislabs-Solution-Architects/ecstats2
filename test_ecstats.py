import pytest
import datetime
import configparser
import boto3
from unittest.mock import Mock, patch
import os
import sys
import tempfile
import openpyxl

# Import the module under test
import ecstats


def create_paginator_side_effect(clusters=None, reserved_instances=None):
    """Shared helper to create paginator side effect with custom data."""
    if clusters is None:
        clusters = []
    if reserved_instances is None:
        reserved_instances = []

    def get_paginator_side_effect(paginator_name):
        mock_paginator = Mock()
        if paginator_name == "describe_cache_clusters":
            mock_paginator.paginate.return_value = [{"CacheClusters": clusters}]
        elif paginator_name == "describe_reserved_cache_nodes":
            mock_paginator.paginate.return_value = [
                {"ReservedCacheNodes": reserved_instances}
            ]
        return mock_paginator

    return get_paginator_side_effect


class TestMetricDefinitions:
    """Test metric definition functions."""

    def test_get_max_metrics_hourly(self):
        """Test hourly metrics definition."""
        metrics = ecstats.get_max_metrics_hourly()

        assert isinstance(metrics, list)
        assert len(metrics) > 0

        # Check structure of metrics
        for metric in metrics:
            assert len(metric) == 3
            metric_name, aggregation, period = metric
            assert isinstance(metric_name, str)
            assert aggregation == "Maximum"
            assert period == ecstats.SECONDS_IN_HOUR

    def test_get_max_metrics_weekly(self):
        """Test weekly metrics definition."""
        metrics = ecstats.get_max_metrics_weekly()

        assert isinstance(metrics, list)
        assert len(metrics) > 0

        # Check structure of metrics
        for metric in metrics:
            assert len(metric) == 3
            metric_name, aggregation, period = metric
            assert isinstance(metric_name, str)
            assert aggregation == "Maximum"
            assert (
                period == ecstats.SECONDS_IN_DAY * ecstats.METRIC_COLLECTION_PERIOD_DAYS
            )


class TestUtilityFunctions:
    """Test utility functions."""

    def test_calc_expiry_time(self):
        """Test expiry time calculation."""
        # Test future date
        future_date = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        future_date = future_date.replace(tzinfo=datetime.timezone.utc)

        days_until_expiry = ecstats.calc_expiry_time(future_date)
        assert 29 <= days_until_expiry <= 30  # Allow for small timing differences

        # Test past date
        past_date = datetime.datetime.utcnow() - datetime.timedelta(days=10)
        past_date = past_date.replace(tzinfo=datetime.timezone.utc)

        days_until_expiry = ecstats.calc_expiry_time(past_date)
        assert days_until_expiry < 0

    def test_parse_major_version(self):
        """Test Redis/Valkey major version parsing."""
        assert ecstats.parse_major_version("7.1") == 7
        assert ecstats.parse_major_version("8.0.1") == 8
        assert ecstats.parse_major_version("") is None
        assert ecstats.parse_major_version(None) is None
        assert ecstats.parse_major_version("unknown") is None


class TestClusterInfo:
    """Test cluster information retrieval."""

    @patch("boto3.Session")
    def test_get_clusters_info_basic_structure(self, mock_session):
        """Test basic structure of get_clusters_info return value."""
        # Mock the session and clients
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        mock_elasticache_client = Mock()
        mock_session_instance.client.return_value = mock_elasticache_client

        # Use helper to create paginator side effect
        clusters = [
            {
                "CacheClusterId": "test-cluster-001",
                "CacheClusterStatus": "available",
                "Engine": "redis",
                "EngineVersion": "7.1",
                "CacheNodeType": "cache.t3.micro",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            }
        ]
        mock_elasticache_client.get_paginator.side_effect = (
            create_paginator_side_effect(clusters)
        )

        # Mock describe_snapshots
        mock_elasticache_client.describe_snapshots.return_value = {"Snapshots": []}

        result = ecstats.get_clusters_info(mock_session_instance)

        assert "elc_running_instances" in result
        assert "elc_reserved_instances" in result
        assert "elc_serverless_caches" in result
        assert "snapshots" in result
        assert isinstance(result["elc_running_instances"], dict)
        assert isinstance(result["elc_reserved_instances"], dict)
        assert isinstance(result["elc_serverless_caches"], dict)
        assert isinstance(result["snapshots"], dict)
        assert (
            result["elc_running_instances"]["test-cluster-001"]["EngineVersion"]
            == "7.1"
        )

    @patch("boto3.Session")
    def test_get_clusters_info_redis_engine_only(self, mock_session):
        """Test that Redis engine clusters are correctly included."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        mock_elasticache_client = Mock()
        mock_session_instance.client.return_value = mock_elasticache_client

        clusters = [
            {
                "CacheClusterId": "redis-cluster-001",
                "CacheClusterStatus": "available",
                "Engine": "redis",
                "EngineVersion": "7.0",
                "CacheNodeType": "cache.r6g.large",
                "CacheNodes": [
                    {"CacheNodeId": "0001"},
                    {"CacheNodeId": "0002"},
                ],
            },
            {
                "CacheClusterId": "redis-cluster-002",
                "CacheClusterStatus": "available",
                "Engine": "redis",
                "EngineVersion": "6.2",
                "CacheNodeType": "cache.t3.medium",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
        ]
        mock_elasticache_client.get_paginator.side_effect = (
            create_paginator_side_effect(clusters)
        )
        mock_elasticache_client.describe_snapshots.return_value = {"Snapshots": []}

        result = ecstats.get_clusters_info(mock_session_instance)

        assert len(result["elc_running_instances"]) == 2
        assert "redis-cluster-001" in result["elc_running_instances"]
        assert "redis-cluster-002" in result["elc_running_instances"]

        # Verify Redis engine is preserved
        for cluster_id, cluster_info in result["elc_running_instances"].items():
            assert cluster_info["Engine"] == "redis"

    @patch("boto3.Session")
    def test_get_clusters_info_valkey_engine_only(self, mock_session):
        """Test that Valkey engine clusters are correctly included."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        mock_elasticache_client = Mock()
        mock_session_instance.client.return_value = mock_elasticache_client

        clusters = [
            {
                "CacheClusterId": "valkey-cluster-001",
                "CacheClusterStatus": "available",
                "Engine": "valkey",
                "EngineVersion": "8.0",
                "CacheNodeType": "cache.r7g.xlarge",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
            {
                "CacheClusterId": "valkey-cluster-002",
                "CacheClusterStatus": "available",
                "Engine": "valkey",
                "EngineVersion": "7.2",
                "CacheNodeType": "cache.m6g.large",
                "CacheNodes": [
                    {"CacheNodeId": "0001"},
                    {"CacheNodeId": "0002"},
                    {"CacheNodeId": "0003"},
                ],
            },
        ]
        mock_elasticache_client.get_paginator.side_effect = (
            create_paginator_side_effect(clusters)
        )
        mock_elasticache_client.describe_snapshots.return_value = {"Snapshots": []}

        result = ecstats.get_clusters_info(mock_session_instance)

        assert len(result["elc_running_instances"]) == 2
        assert "valkey-cluster-001" in result["elc_running_instances"]
        assert "valkey-cluster-002" in result["elc_running_instances"]

        # Verify Valkey engine is preserved
        for cluster_info in result["elc_running_instances"].values():
            assert cluster_info["Engine"] == "valkey"
            assert cluster_info["EngineVersion"] in ["8.0", "7.2"]

    @patch("boto3.Session")
    def test_get_clusters_info_filters_redis_valkey_only(self, mock_session):
        """Test that only Redis and Valkey engines are included, other engines filtered out."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        mock_elasticache_client = Mock()
        mock_session_instance.client.return_value = mock_elasticache_client

        clusters = [
            {
                "CacheClusterId": "redis-cluster",
                "CacheClusterStatus": "available",
                "Engine": "redis",
                "CacheNodeType": "cache.r6g.large",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
            {
                "CacheClusterId": "valkey-cluster",
                "CacheClusterStatus": "available",
                "Engine": "valkey",
                "CacheNodeType": "cache.m6g.medium",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
            {
                "CacheClusterId": "memcached-cluster",
                "CacheClusterStatus": "available",
                "Engine": "memcached",
                "CacheNodeType": "cache.t3.micro",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
        ]
        mock_elasticache_client.get_paginator.side_effect = (
            create_paginator_side_effect(clusters)
        )
        mock_elasticache_client.describe_snapshots.return_value = {"Snapshots": []}

        result = ecstats.get_clusters_info(mock_session_instance)

        # Verify only Redis and Valkey clusters are included
        assert len(result["elc_running_instances"]) == 2
        assert "redis-cluster" in result["elc_running_instances"]
        assert "valkey-cluster" in result["elc_running_instances"]
        assert "memcached-cluster" not in result["elc_running_instances"]

        # Verify engines are correctly preserved
        assert result["elc_running_instances"]["redis-cluster"]["Engine"] == "redis"
        assert result["elc_running_instances"]["valkey-cluster"]["Engine"] == "valkey"

    @patch("boto3.Session")
    def test_get_clusters_info_status_filtering(self, mock_session):
        """Test that only 'available' status clusters are included."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        mock_elasticache_client = Mock()
        mock_session_instance.client.return_value = mock_elasticache_client

        clusters = [
            {
                "CacheClusterId": "available-redis",
                "CacheClusterStatus": "available",
                "Engine": "redis",
                "CacheNodeType": "cache.t3.micro",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
            {
                "CacheClusterId": "creating-redis",
                "CacheClusterStatus": "creating",
                "Engine": "redis",
                "CacheNodeType": "cache.t3.micro",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
            {
                "CacheClusterId": "deleting-valkey",
                "CacheClusterStatus": "deleting",
                "Engine": "valkey",
                "CacheNodeType": "cache.t3.micro",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
            {
                "CacheClusterId": "available-valkey",
                "CacheClusterStatus": "available",
                "Engine": "valkey",
                "CacheNodeType": "cache.t3.micro",
                "CacheNodes": [{"CacheNodeId": "0001"}],
            },
        ]
        mock_elasticache_client.get_paginator.side_effect = (
            create_paginator_side_effect(clusters)
        )
        mock_elasticache_client.describe_snapshots.return_value = {"Snapshots": []}

        result = ecstats.get_clusters_info(mock_session_instance)

        # Only available clusters should be included
        assert len(result["elc_running_instances"]) == 2
        assert "available-redis" in result["elc_running_instances"]
        assert "available-valkey" in result["elc_running_instances"]
        assert "creating-redis" not in result["elc_running_instances"]
        assert "deleting-valkey" not in result["elc_running_instances"]

    @patch("boto3.Session")
    def test_get_clusters_info_with_reserved_instances(self, mock_session):
        """Test processing of reserved instances for Redis and Valkey."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        mock_elasticache_client = Mock()
        mock_session_instance.client.return_value = mock_elasticache_client

        reserved_instances = [
            {
                "CacheNodeType": "cache.r6g.large",
                "State": "active",
                "ProductDescription": "redis",
                "CacheNodeCount": 3,
                "StartTime": datetime.datetime.now() - datetime.timedelta(days=30),
                "Duration": 31536000,  # 1 year in seconds
            },
            {
                "CacheNodeType": "cache.m6g.xlarge",
                "State": "active",
                "ProductDescription": "valkey",
                "CacheNodeCount": 2,
                "StartTime": datetime.datetime.now() - datetime.timedelta(days=60),
                "Duration": 94608000,  # 3 years in seconds
            },
            {
                "CacheNodeType": "cache.t3.micro",
                "State": "retired",
                "ProductDescription": "redis",
                "CacheNodeCount": 1,
                "StartTime": datetime.datetime.now() - datetime.timedelta(days=400),
                "Duration": 31536000,
            },
            {
                "CacheNodeType": "cache.r5.large",
                "State": "active",
                "ProductDescription": "memcached",
                "CacheNodeCount": 2,
                "StartTime": datetime.datetime.now() - datetime.timedelta(days=30),
                "Duration": 31536000,
            },
        ]
        mock_elasticache_client.get_paginator.side_effect = (
            create_paginator_side_effect(
                clusters=[], reserved_instances=reserved_instances
            )
        )
        mock_elasticache_client.describe_snapshots.return_value = {"Snapshots": []}

        result = ecstats.get_clusters_info(mock_session_instance)

        # Should only include active Redis and Valkey reserved instances
        assert len(result["elc_reserved_instances"]) == 2
        assert "cache.r6g.large" in result["elc_reserved_instances"]
        assert "cache.m6g.xlarge" in result["elc_reserved_instances"]
        assert "cache.t3.micro" not in result["elc_reserved_instances"]  # retired
        assert "cache.r5.large" not in result["elc_reserved_instances"]  # memcached

        # Verify reserved instance details
        redis_ri = result["elc_reserved_instances"]["cache.r6g.large"]
        valkey_ri = result["elc_reserved_instances"]["cache.m6g.xlarge"]

        assert redis_ri["count"] == 3
        assert valkey_ri["count"] == 2
        assert isinstance(redis_ri["expiry_time"], int)
        assert isinstance(valkey_ri["expiry_time"], int)

    @patch("boto3.Session")
    def test_get_clusters_info_with_serverless_cache(self, mock_session):
        """Test processing of available serverless Redis caches."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        mock_elasticache_client = Mock()
        mock_session_instance.client.return_value = mock_elasticache_client
        mock_elasticache_client.get_paginator.side_effect = (
            create_paginator_side_effect()
        )
        mock_elasticache_client.describe_snapshots.return_value = {"Snapshots": []}
        mock_elasticache_client.describe_serverless_caches.return_value = {
            "ServerlessCaches": [
                {
                    "ServerlessCacheName": "serverless-redis",
                    "Status": "available",
                    "Engine": "redis",
                    "FullEngineVersion": "7.1",
                    "SnapshotRetentionLimit": 0,
                },
                {
                    "ServerlessCacheName": "serverless-creating",
                    "Status": "creating",
                    "Engine": "redis",
                },
            ]
        }

        result = ecstats.get_clusters_info(mock_session_instance)

        assert len(result["elc_serverless_caches"]) == 1
        assert "serverless-redis" in result["elc_serverless_caches"]
        assert "serverless-creating" not in result["elc_serverless_caches"]


class TestMetricRetrieval:
    """Test metric retrieval functions."""

    @patch("datetime.date")
    def test_get_metric(self, mock_date):
        """Test get_metric function."""
        # Mock date.today()
        mock_today = datetime.date(2023, 1, 8)
        mock_date.today.return_value = mock_today

        mock_cloudwatch = Mock()
        mock_cloudwatch.get_metric_statistics.return_value = {
            "Datapoints": [{"Maximum": 100.0}, {"Maximum": 150.0}, {"Maximum": 120.0}]
        }

        result = ecstats.get_metric(
            mock_cloudwatch, "test-cluster", "0001", "CurrItems", "Maximum", 3600
        )

        assert result == [100.0, 150.0, 120.0]

        # Verify the CloudWatch call
        mock_cloudwatch.get_metric_statistics.assert_called_once()
        call_args = mock_cloudwatch.get_metric_statistics.call_args

        assert call_args[1]["Namespace"] == "AWS/ElastiCache"
        assert call_args[1]["MetricName"] == "CurrItems"
        assert call_args[1]["Statistics"] == ["Maximum"]

    def test_get_metric_curr(self):
        """Test get_metric_curr function."""
        mock_cloudwatch = Mock()
        mock_cloudwatch.get_metric_data.return_value = {
            "MetricDataResults": [{"Values": [1.0]}]
        }

        result = ecstats.get_metric_curr(
            mock_cloudwatch, "test-cluster", "0001", "IsMaster"
        )

        assert result == 1.0

        # Test empty response
        mock_cloudwatch.get_metric_data.return_value = {
            "MetricDataResults": [{"Values": []}]
        }

        result = ecstats.get_metric_curr(
            mock_cloudwatch, "test-cluster", "0001", "IsMaster"
        )

        assert result == -1

    @patch("datetime.date")
    def test_get_serverless_metric(self, mock_date):
        """Test serverless CloudWatch metric retrieval uses clusterId dimension."""
        mock_today = datetime.date(2023, 1, 8)
        mock_date.today.return_value = mock_today

        mock_cloudwatch = Mock()
        mock_cloudwatch.get_metric_statistics.return_value = {
            "Datapoints": [{"Maximum": 42.0}]
        }

        result = ecstats.get_serverless_metric(
            mock_cloudwatch, "serverless-redis", "CurrItems", "Maximum", 3600
        )

        assert result == [42.0]
        call_args = mock_cloudwatch.get_metric_statistics.call_args
        assert call_args[1]["Dimensions"] == [
            {"Name": "clusterId", "Value": "serverless-redis"}
        ]


class TestWorkbookOperations:
    """Test Excel workbook operations."""

    def test_create_workbook(self):
        """Test workbook creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            wb = ecstats.create_workbook(temp_dir, "test-section", "us-west-1")

            assert isinstance(wb, openpyxl.Workbook)
            assert len(wb.sheetnames) == 3
            assert ecstats.RUNNING_INSTANCES_WORKSHEET_NAME in wb.sheetnames
            assert ecstats.RESERVED_INSTANCES_WORKSHEET_NAME in wb.sheetnames
            assert ecstats.UPGRADE_READINESS_WORKSHEET_NAME in wb.sheetnames

            # Check running instances worksheet headers
            ws = wb[ecstats.RUNNING_INSTANCES_WORKSHEET_NAME]
            headers = [cell.value for cell in ws[1]]

            expected_base_headers = [
                "Source",
                "ClusterId",
                "NodeId",
                "NodeRole",
                "NodeType",
                "Region",
                "SnapshotRetentionLimit",
            ]

            for header in expected_base_headers:
                assert header in headers

            # Should have metrics from both weekly and hourly
            assert "Engine" in headers
            assert "EngineVersion" in headers
            assert "QPF" in headers

            upgrade_ws = wb[ecstats.UPGRADE_READINESS_WORKSHEET_NAME]
            upgrade_headers = [cell.value for cell in upgrade_ws[1]]
            assert upgrade_headers == [
                "Source",
                "ClusterId",
                "NodeId",
                "NodeRole",
                "Engine",
                "EngineVersion",
                "Severity",
                "Category",
                "Signal",
                "ObservedValue",
                "Recommendation",
            ]

    def test_get_running_instances_metrics_includes_engine_version(self):
        """Test running instance rows include engine family and version."""
        wb = ecstats.create_workbook(".", "test-section", "us-west-1")
        clusters_info = {
            "elc_running_instances": {
                "test-cluster-001": {
                    "CacheClusterId": "test-cluster-001",
                    "CacheClusterStatus": "available",
                    "Engine": "valkey",
                    "EngineVersion": "8.0",
                    "CacheNodeType": "cache.t3.micro",
                    "PreferredAvailabilityZone": "us-west-1a",
                    "CacheNodes": [{"CacheNodeId": "0001"}],
                }
            },
            "elc_reserved_instances": {},
            "snapshots": {},
        }
        mock_session = Mock()
        mock_cloudwatch = Mock()
        mock_session.client.return_value = mock_cloudwatch

        with patch("ecstats.get_metric_curr", return_value=1.0), patch(
            "ecstats.get_metric", return_value=[60.0]
        ):
            wb = ecstats.get_running_instances_metrics(wb, clusters_info, mock_session)

        ws = wb[ecstats.RUNNING_INSTANCES_WORKSHEET_NAME]
        headers = [cell.value for cell in ws[1]]
        row = [cell.value for cell in ws[2]]

        assert row[headers.index("Engine")] == "valkey"
        assert row[headers.index("EngineVersion")] == "8.0"
        assert row[headers.index("QPF")] == ""

    def test_get_running_instances_metrics_adds_upgrade_findings(self):
        """Test readiness sheet flags Redis upgrade roadblocks and deprecated command families."""
        wb = ecstats.create_workbook(".", "test-section", "us-west-1")
        clusters_info = {
            "elc_running_instances": {
                "test-cluster-001": {
                    "CacheClusterId": "test-cluster-001",
                    "CacheClusterStatus": "available",
                    "Engine": "redis",
                    "EngineVersion": "6.2",
                    "CacheNodeType": "cache.t3.micro",
                    "PreferredAvailabilityZone": "us-west-1a",
                    "CacheNodes": [{"CacheNodeId": "0001"}],
                }
            },
            "elc_reserved_instances": {},
            "snapshots": {"test-cluster-001": 7},
        }
        mock_session = Mock()
        mock_cloudwatch = Mock()
        mock_session.client.return_value = mock_cloudwatch

        def metric_side_effect(_cloud_watch, _cluster_id, _node, metric, *_args):
            if metric == "StringBasedCmds":
                return [600.0]
            if metric == "AuthenticationFailures":
                return [1.0]
            if metric == "EngineCPUUtilization":
                return [95.0]
            return [0.0]

        with patch("ecstats.get_metric_curr", return_value=1.0), patch(
            "ecstats.get_metric", side_effect=metric_side_effect
        ):
            wb = ecstats.get_running_instances_metrics(wb, clusters_info, mock_session)

        ws = wb[ecstats.UPGRADE_READINESS_WORKSHEET_NAME]
        headers = [cell.value for cell in ws[1]]
        rows = [[cell.value for cell in row] for row in ws.iter_rows(min_row=2)]

        signals = [row[headers.index("Signal")] for row in rows]
        categories = [row[headers.index("Category")] for row in rows]

        assert "EngineVersion" in signals
        assert "AuthenticationFailures" in signals
        assert "StringBasedCmds" in signals
        assert "EngineCPUUtilization" in signals
        assert "PotentialDeprecatedCommands" in categories

        deprecated_row = rows[signals.index("StringBasedCmds")]
        recommendation = deprecated_row[headers.index("Recommendation")]
        assert "SETEX -> SET EX" in recommendation

    def test_append_upgrade_readiness_issues_records_no_findings(self):
        """Test clean nodes get an explicit no-roadblocks row."""
        wb = ecstats.create_workbook(".", "test-section", "us-west-1")
        ws = wb[ecstats.UPGRADE_READINESS_WORKSHEET_NAME]
        instance_details = {
            "Engine": "redis",
            "EngineVersion": "%s.0" % ecstats.TARGET_REDIS_MAJOR_VERSION,
        }

        ecstats.append_upgrade_readiness_issues(
            ws,
            "test-cluster",
            "test-node",
            "Master",
            instance_details,
            7,
            {},
        )

        headers = [cell.value for cell in ws[1]]
        row = [cell.value for cell in ws[2]]

        assert row[headers.index("Severity")] == "Info"
        assert row[headers.index("Signal")] == "NoRoadblocksDetected"

    def test_get_running_instances_metrics_includes_serverless_cache(self):
        """Test serverless cache rows are included in workbook output."""
        wb = ecstats.create_workbook(".", "test-section", "us-west-2")
        clusters_info = {
            "elc_running_instances": {},
            "elc_reserved_instances": {},
            "elc_serverless_caches": {
                "serverless-redis": {
                    "ServerlessCacheName": "serverless-redis",
                    "Status": "available",
                    "Engine": "redis",
                    "FullEngineVersion": "7.1",
                    "SnapshotRetentionLimit": 0,
                    "ARN": "arn:aws:elasticache:us-west-2:123456789012:serverlesscache:serverless-redis",
                }
            },
            "snapshots": {},
        }
        mock_session = Mock()
        mock_cloudwatch = Mock()
        mock_session.client.return_value = mock_cloudwatch

        with patch("ecstats.get_serverless_metric", return_value=[12.0]):
            wb = ecstats.get_running_instances_metrics(wb, clusters_info, mock_session)

        ws = wb[ecstats.RUNNING_INSTANCES_WORKSHEET_NAME]
        headers = [cell.value for cell in ws[1]]
        row = [cell.value for cell in ws[2]]

        assert row[headers.index("Source")] == "EC-Serverless"
        assert row[headers.index("ClusterId")] == "serverless-redis"
        assert row[headers.index("NodeRole")] == "Serverless"
        assert row[headers.index("NodeType")] == "serverless"
        assert row[headers.index("Region")] == "us-west-2"
        assert row[headers.index("CurrItems")] == 12.0
        assert row[headers.index("EngineVersion")] == "7.1"

        upgrade_ws = wb[ecstats.UPGRADE_READINESS_WORKSHEET_NAME]
        upgrade_headers = [cell.value for cell in upgrade_ws[1]]
        upgrade_row = [cell.value for cell in upgrade_ws[2]]
        assert upgrade_row[upgrade_headers.index("Source")] == "EC-Serverless"


class TestIntegration:
    """Integration tests."""

    def test_process_aws_account_uses_direct_access_keys_from_config(self):
        """Direct config credentials should be passed into boto3.Session."""
        config = configparser.ConfigParser()
        config.add_section("production")
        config.set("production", "aws_access_key_id", "test-key")
        config.set("production", "aws_secret_access_key", "test-secret")
        config.set("production", "aws_session_token", "test-token")
        config.set("production", "region_name", "us-west-1")

        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "boto3.Session"
        ) as mock_session, patch("ecstats.get_clusters_info") as mock_clusters, patch(
            "ecstats.get_running_instances_metrics"
        ) as mock_running, patch(
            "ecstats.get_reserved_instances_info"
        ) as mock_reserved, patch(
            "ecstats.create_workbook"
        ) as mock_workbook:
            mock_session_instance = Mock()
            mock_session.return_value = mock_session_instance

            mock_sts_client = Mock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": "arn:aws:sts::123456789012:assumed-role/TestRole/test-session"
            }
            mock_session_instance.client.return_value = mock_sts_client

            mock_clusters.return_value = {
                "elc_running_instances": {},
                "elc_reserved_instances": {},
                "snapshots": {},
            }

            workbook = Mock()
            mock_workbook.return_value = workbook
            mock_running.return_value = workbook
            mock_reserved.return_value = workbook

            ecstats.process_aws_account(config, "production", temp_dir)

            mock_session.assert_called_once_with(
                aws_access_key_id="test-key",
                aws_secret_access_key="test-secret",
                aws_session_token="test-token",
                region_name="us-west-1",
            )

    def test_process_aws_account_prefers_access_keys_over_profile(self):
        """Explicit config credentials should take precedence over profile_name."""
        config = configparser.ConfigParser()
        config.add_section("production")
        config.set("production", "aws_access_key_id", "test-key")
        config.set("production", "aws_secret_access_key", "test-secret")
        config.set("production", "profile_name", "test-profile")
        config.set("production", "region_name", "us-west-1")

        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "boto3.Session"
        ) as mock_session, patch("ecstats.get_clusters_info") as mock_clusters, patch(
            "ecstats.get_running_instances_metrics"
        ) as mock_running, patch(
            "ecstats.get_reserved_instances_info"
        ) as mock_reserved, patch(
            "ecstats.create_workbook"
        ) as mock_workbook:
            mock_session_instance = Mock()
            mock_session.return_value = mock_session_instance

            mock_sts_client = Mock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": "arn:aws:sts::123456789012:assumed-role/TestRole/test-session"
            }
            mock_session_instance.client.return_value = mock_sts_client

            mock_clusters.return_value = {
                "elc_running_instances": {},
                "elc_reserved_instances": {},
                "snapshots": {},
            }

            workbook = Mock()
            mock_workbook.return_value = workbook
            mock_running.return_value = workbook
            mock_reserved.return_value = workbook

            ecstats.process_aws_account(config, "production", temp_dir)

            mock_session.assert_called_once_with(
                aws_access_key_id="test-key",
                aws_secret_access_key="test-secret",
                region_name="us-west-1",
            )

    def test_end_to_end_workflow_mock(self):
        """Test end-to-end workflow with comprehensive mocking."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = os.path.join(temp_dir, "test_config.ini")

            # Create test config
            config = configparser.ConfigParser()
            config.add_section("production")
            config.set("production", "aws_access_key_id", "test-key")
            config.set("production", "aws_secret_access_key", "test-secret")
            config.set("production", "region_name", "us-west-1")

            with open(config_file, "w") as f:
                config.write(f)

            # Mock all AWS interactions
            with patch("boto3.Session") as mock_session, patch(
                "sys.argv", ["ecstats.py", "-c", config_file, "-d", temp_dir]
            ):

                # Setup mock session and clients
                mock_session_instance = Mock()
                mock_session.return_value = mock_session_instance

                mock_elasticache_client = Mock()
                mock_cloudwatch_client = Mock()
                mock_sts_client = Mock()

                mock_sts_client.get_caller_identity.return_value = {
                    "UserId": "test-user",
                    "Account": "123456789012",
                    "Arn": "arn:aws:sts::123456789012:assumed-role/TestRole/test-session",
                }

                def client_side_effect(service_name):
                    if service_name == "elasticache":
                        return mock_elasticache_client
                    elif service_name == "cloudwatch":
                        return mock_cloudwatch_client
                    elif service_name == "sts":
                        return mock_sts_client
                    return Mock()

                mock_session_instance.client.side_effect = client_side_effect

                # Mock ElastiCache responses using helper
                clusters = [
                    {
                        "CacheClusterId": "test-cluster-001",
                        "CacheClusterStatus": "available",
                        "Engine": "redis",
                        "EngineVersion": "7.1",
                        "CacheNodeType": "cache.t3.micro",
                        "PreferredAvailabilityZone": "us-west-1a",
                        "CacheNodes": [{"CacheNodeId": "0001"}],
                    }
                ]
                mock_elasticache_client.get_paginator.side_effect = (
                    create_paginator_side_effect(clusters)
                )

                mock_elasticache_client.describe_snapshots.return_value = {
                    "Snapshots": []
                }

                # Mock CloudWatch responses
                mock_cloudwatch_client.get_metric_statistics.return_value = {
                    "Datapoints": [{"Maximum": 100.0}]
                }
                mock_cloudwatch_client.get_metric_data.return_value = {
                    "MetricDataResults": [{"Values": [1.0]}]
                }

                # Run main function
                ecstats.main()

                # Verify output file was created
                expected_output = os.path.join(temp_dir, "production-us-west-1.xlsx")
                assert os.path.exists(expected_output)

                # Verify the Excel file structure
                wb = openpyxl.load_workbook(expected_output)
                assert ecstats.RUNNING_INSTANCES_WORKSHEET_NAME in wb.sheetnames
                assert ecstats.RESERVED_INSTANCES_WORKSHEET_NAME in wb.sheetnames
                ws = wb[ecstats.RUNNING_INSTANCES_WORKSHEET_NAME]
                headers = [cell.value for cell in ws[1]]
                row = [cell.value for cell in ws[2]]
                assert row[headers.index("Engine")] == "redis"
                assert row[headers.index("EngineVersion")] == "7.1"


if __name__ == "__main__":
    pytest.main([__file__])
