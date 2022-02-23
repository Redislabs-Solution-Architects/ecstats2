import os
import sys
import datetime
import configparser
import optparse
import boto3
import openpyxl

# Metric Collection Period (in days)
METRIC_COLLECTION_PERIOD_DAYS = 7

SECONDS_IN_MINUTE = 60
SECONDS_IN_HOUR = 60 * SECONDS_IN_MINUTE
SECONDS_IN_DAY = 24 * SECONDS_IN_HOUR

RUNNING_INSTANCES_WORKSHEET_NAME = 'ClusterData'
RESERVED_INSTANCES_WORKSHEET_NAME = 'ReservedData'

def get_avg_metrics():
    metrics = [
        ('GetTypeCmds', 'Average', SECONDS_IN_HOUR),
        ('SetTypeCmds', 'Average', SECONDS_IN_HOUR),
        ('HashBasedCmds', 'Average', SECONDS_IN_HOUR),
        ('HyperLogLogBasedCmds', 'Average', SECONDS_IN_HOUR),
        ('KeyBasedCmds', 'Average', SECONDS_IN_HOUR),
        ('ListBasedCmds', 'Average', SECONDS_IN_HOUR),
        ('SetBasedCmds', 'Average', SECONDS_IN_HOUR),
        ('SortedSetBasedCmds', 'Average', SECONDS_IN_HOUR),
        ('StringBasedCmds', 'Average', SECONDS_IN_HOUR),
        ('StreamBasedCmds', 'Average', SECONDS_IN_HOUR)
    ]
    return metrics

def get_max_metrics():
    metrics = [
        ('CurrItems', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('BytesUsedForCache', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('CacheHits', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('CacheMisses', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('CurrConnections', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('NetworkBytesIn', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('NetworkBytesOut', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('NetworkPacketsIn', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('NetworkPacketsOut', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('EngineCPUUtilization', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('Evictions', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('ReplicationBytes', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ('ReplicationLag', 'Maximum', SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS)
    ]
    return metrics

def calc_expiry_time(expiry):
    """Calculate the number of days until the reserved instance expires.
    Args:
        expiry (DateTime): A timezone-aware DateTime object of the date when
            the reserved instance will expire.
    Returns:
        The number of days between the expiration date and now.
    """
    return (expiry.replace(tzinfo=None) - datetime.datetime.utcnow()).days

def get_clusters_info(session):
    """Calculate the running/reserved instances in ElastiCache.
    Args:
        session (:boto3:session.Session): The authenticated boto3 session.
    Returns:
        A dictionary of the running/reserved instances for ElastiCache nodes.
    """
    conn = session.client('elasticache')
    results = {
        'elc_running_instances': {},
        'elc_reserved_instances': {},
    }

    paginator = conn.get_paginator('describe_cache_clusters')
    page_iterator = paginator.paginate(ShowCacheNodeInfo=True)
    # Loop through running ElastiCache instance and record their engine,
    # type, and name.
    for page in page_iterator:
        for instance in page['CacheClusters']:
            if (instance['CacheClusterStatus'] == 'available' and instance['Engine'] == 'redis'):
                cluster_id = instance['CacheClusterId']
                results['elc_running_instances'][cluster_id] = instance

    paginator = conn.get_paginator('describe_reserved_cache_nodes')
    page_iterator = paginator.paginate()

    # Loop through active ElastiCache RIs and record their type and engine.
    for page in page_iterator:
        for reserved_instance in page['ReservedCacheNodes']:
            if (reserved_instance['State'] == 'active' and reserved_instance['ProductDescription'] == 'redis'):
                instance_type = reserved_instance['CacheNodeType']
                # No end datetime is returned, so calculate from 'StartTime'
                # (a `DateTime`) and 'Duration' in seconds (integer)
                expiry_time = reserved_instance['StartTime'] + datetime.timedelta(seconds=reserved_instance['Duration'])
                results['elc_reserved_instances'][instance_type] = {
                    'count': reserved_instance['CacheNodeCount'],
                    'expiry_time': calc_expiry_time(expiry=expiry_time)
                }
    return results

def get_metric(cloud_watch, cluster_id, node, metric, aggregation, period):
    """Write node related metrics to file
    Args:
        ClusterId, node and metric to write
    Returns:
    The metric value
    """
    today = datetime.date.today() + datetime.timedelta(days=1)
    then = today - datetime.timedelta(days=METRIC_COLLECTION_PERIOD_DAYS)
    response = cloud_watch.get_metric_statistics(
        Namespace='AWS/ElastiCache',
        MetricName=metric,
        Dimensions=[
            {'Name': 'CacheClusterId', 'Value': cluster_id},
            {'Name': 'CacheNodeId', 'Value': node}
        ],
        StartTime=then.isoformat(),
        EndTime=today.isoformat(),
        Period=period,
        Statistics=[aggregation]
    )

    raw_data = [rec[aggregation] for rec in response['Datapoints']]
    return raw_data

def create_workbook(outDir, section, region_name):
    """Create an empty workbook dataframe with headers
    Args:
    Returns:
    The newely created pandas dataframe
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = RUNNING_INSTANCES_WORKSHEET_NAME

    df_columns = ["ClusterId", "NodeId", "NodeType", "Region"]
    for metric, _, _ in get_max_metrics():
        df_columns.append(('%s (max over last week)' % metric))
    for metric, _, _ in get_avg_metrics():
        df_columns.append(('%s (peak last week / hour)' % metric))
    ws.append(df_columns)

    ws = wb.create_sheet(RESERVED_INSTANCES_WORKSHEET_NAME)    
    df_columns = ["Instance Type", "Count", "Remaining Time (days)"]
    ws.append(df_columns)    
    return wb

def get_running_instances_metrics(wb, clusters_info, session):
    """
    Get all the metrics for the clusters in the given set of clusters
    Args:
        The cluster information dictionary
    Returns:
    """
    cloud_watch = session.client('cloudwatch')
    running_instances = clusters_info['elc_running_instances']
    ws = wb[RUNNING_INSTANCES_WORKSHEET_NAME]
    row = []

    for instanceId, instanceDetails in running_instances.items():
        for node in instanceDetails.get('CacheNodes'):
            print("Fetching node %s details" % (instanceDetails['CacheClusterId']))
            if 'ReplicationGroupId' in instanceDetails:
                row.append("%s" % instanceDetails['ReplicationGroupId'])
            else:
                row.append("")

            row.append("%s" % instanceId)
            row.append("%s" % instanceDetails['CacheNodeType'])
            row.append("%s" % instanceDetails['PreferredAvailabilityZone'])
            for (metric, aggregation, period) in get_max_metrics():
                data_points = get_metric(
                    cloud_watch,
                    instanceId,
                    node.get('CacheNodeId'),
                    metric,
                    aggregation,
                    period
                )
                data_point = 0 if len(data_points) == 0 else data_points[0]
                row.append(data_point)
            for (metric, aggregation, period) in get_avg_metrics():
                data_points = get_metric(
                    cloud_watch,
                    instanceId,
                    node.get('CacheNodeId'),
                    metric,
                    aggregation,
                    period
                )
                data_point = 0 if len(data_points) == 0 else max(data_points)
                row.append(data_point)
            ws.append(row)
            row = []
    return wb

def get_reserved_instances_info(wb, clusters_info):
    reserved_instances = clusters_info['elc_reserved_instances']        
    ws = wb[RESERVED_INSTANCES_WORKSHEET_NAME]
    for instanceId, instanceDetails in reserved_instances.items():
        ws.append([
            ("%s" % instanceId),
            ("%s" % instanceDetails['count']),
            ("%s," % instanceDetails['expiry_time'])
        ])
    return wb

def process_aws_account(config, section, outDir):
    # connect to ElastiCache
    # aws key, secret and region
    aws_access_key_id = config.get(section, 'aws_access_key_id')
    aws_secret_access_key = config.get(section, 'aws_secret_access_key')
    region_name = config.get(section, 'region_name')

    if config.has_option(section, 'aws_session_token'):
        aws_session_token = config.get(section, 'aws_session_token')
    else:
        aws_session_token = None

    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
	    aws_session_token=aws_session_token,
        region_name=region_name
    )

    print(f"Requesting information for the {section} nodes")
    clusters_info = get_clusters_info(session)

    wb = create_workbook(outDir, section, region_name)
    wb = get_running_instances_metrics(wb, clusters_info, session)
    wb = get_reserved_instances_info(wb, clusters_info)

    output_file_path = "%s/%s-%s.xlsx" % (outDir, section, region_name)
    print(f"Writing output file {output_file_path}")
    wb.save(output_file_path)
    print("Done!")

def main():
    parser = optparse.OptionParser()
    parser.add_option(
        "-c", 
        "--config", 
        dest="configFile",
        default="config.ini",        
        help="The filename for configuration file. By default the script will try to open the config.ini file.", 
        metavar="FILE"
    )
    parser.add_option(
        "-d", 
        "--out-dir", 
        dest="outDir", 
        default=".",
        help="The directory to output the results. If not the directory does not exist the script will try to create it.", 
        metavar="PATH"
    )

    (options, _) = parser.parse_args()

    if not os.path.isdir(options.outDir):
        os.makedirs(options.outDir)

    if not os.path.isfile(options.configFile):
        print(f"Can't find the specified {options.configFile} configuration file")
        sys.exit(1)

    # Open and parse the configuration file.
    config = configparser.ConfigParser()
    config.read(options.configFile)

    # For each section defined in the config.ini file, the script 
    # will try to fetch the ElastiCache utilization by parsing the 
    # Cloudwatch statistics
    for section in config.sections():
        process_aws_account(config, section, options.outDir)

if __name__ == "__main__":
    main()
