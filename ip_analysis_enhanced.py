#!/usr/bin/env python3
import pandas as pd
import ipaddress
import argparse
import logging
import sys

COLS_TO_KEEP = [
    'sourceIp',
    'sourcePort',
    'destinationIp',
    'destinationPort',
    'transportProtocol'
]

def read_and_process_csv(file_path, os_type, env_type, traffic_type):
    """
    Reads a CSV file containing traffic data, processes it, and returns a DataFrame.

    Args:
        file_path (str): The path to the CSV file.
        os_type (str): The operating system type.
        env_type (str): The environment type.
        traffic_type (str): The type of traffic (inbound or outbound).

    Returns:
        pd.DataFrame: A DataFrame containing the processed traffic data.
    """
    logging.info(f"Reading and processing {traffic_type} file: {file_path}")
    try:
        df = pd.read_csv(file_path, usecols=range(10))
    except FileNotFoundError:
        logging.error(f"Error: {file_path} not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred while reading {file_path}: {e}")
        sys.exit(1)
        
    df.columns = df.columns.str.strip()
    if traffic_type == 'inbound':
        df = df.drop_duplicates(subset=['sourceIp', 'destinationPort'])
    else:
        df = df.drop_duplicates(subset=['destinationIp', 'destinationPort'])
    df = df[df['destinationPort'] != 17472]
    df = df[COLS_TO_KEEP]
    df['OS'] = os_type
    df['Environment'] = env_type
    df['type'] = traffic_type
    return df

def combine_dataframes(inbound_df, outbound_df):
    """
    Combines two DataFrames into one.

    Args:
        inbound_df (pd.DataFrame): The DataFrame containing inbound traffic data.
        outbound_df (pd.DataFrame): The DataFrame containing outbound traffic data.

    Returns:
        pd.DataFrame: A single DataFrame containing both inbound and outbound traffic data.
    """
    logging.info("Combining inbound and outbound dataframes.")
    return pd.concat([inbound_df, outbound_df], ignore_index=True)

def write_to_excel(df, file_path, sheet_name):
    """
    Writes a DataFrame to a new Excel file.

    Args:
        df (pd.DataFrame): The DataFrame to write.
        file_path (str): The path to the output Excel file.
        sheet_name (str): The name of the sheet to create.
    """
    logging.info(f"Writing dataframe to {file_path} in sheet {sheet_name}")
    try:
        with pd.ExcelWriter(file_path) as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)
    except Exception as e:
        logging.error(f"An error occurred while writing to {file_path}: {e}")
        sys.exit(1)

def append_to_excel(df, file_path, sheet_name):
    """
    Appends a DataFrame to an existing Excel file.

    Args:
        df (pd.DataFrame): The DataFrame to append.
        file_path (str): The path to the Excel file.
        sheet_name (str): The name of the sheet to append to.
    """
    logging.info(f"Appending dataframe to {file_path} in sheet {sheet_name}")
    try:
        with pd.ExcelWriter(file_path, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)
    except Exception as e:
        logging.error(f"An error occurred while appending to {file_path}: {e}")
        sys.exit(1)

def read_sg_rules(sg_file, os_type, env_type):
    """
    Reads security group rules from an Excel file.

    Args:
        sg_file (str): The path to the Excel file containing security group rules.
        os_type (str): The operating system type.
        env_type (str): The environment type.

    Returns:
        tuple: A tuple containing two DataFrames: (sg_inbound_df, sg_outbound_df).
    """
    logging.info(f"Reading security group rules from {sg_file}")
    os_sheet_inbound = f"{os_type}-{env_type}-Inbound"
    os_sheet_outbound = f"{os_type}-{env_type}-Outbound"
    try:
        sg_inbound_df = pd.read_excel(sg_file, sheet_name=os_sheet_inbound)
        sg_outbound_df = pd.read_excel(sg_file, sheet_name=os_sheet_outbound)
        return sg_inbound_df, sg_outbound_df
    except FileNotFoundError:
        logging.error(f"Error: {sg_file} not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred while reading {sg_file}: {e}")
        sys.exit(1)


def protocol_in_sg_rules(protocol, sg_protocol_rule):
    """
    Checks if a protocol is allowed by a security group rule.

    Args:
        protocol (str): The protocol to check.
        sg_protocol_rule (str): The security group protocol rule.

    Returns:
        bool: True if the protocol is allowed, False otherwise.
    """
    protocol = str(protocol).strip().upper()
    sg_rule = str(sg_protocol_rule).strip().upper()
    logging.debug(f"Comparing protocol {protocol} with SG rule {sg_rule}")
    if sg_rule == 'ALL':
        return True
    if ',' in sg_rule:
        allowed_protocols = [proto.strip() for proto in sg_rule.split(',')]
        return protocol in allowed_protocols
    return protocol == sg_rule

def port_in_sg_rules(port, sg_port_rule):
    """
    Checks if a port is allowed by a security group rule.

    Args:
        port (int or str): The port to check.
        sg_port_rule (str): The security group port rule.

    Returns:
        bool: True if the port is allowed, False otherwise.
    """
    port = str(port)
    sg_rule = str(sg_port_rule).strip().upper()
    logging.debug(f"Comparing port {port} with SG rule {sg_rule}")
    if sg_rule == 'ALL':
        return True
    if '-' in sg_rule:  
        try:
            start, end = map(int, sg_rule.split('-'))
            return int(port) >= start and int(port) <= end
        except Exception:
            return False
    return port == sg_rule

def ip_in_sg_rule_ip(ip, sg_ip_rule):
    """
    Checks if an IP address is within a security group rule's IP range or subnet.

    Args:
        ip (str): The IP address to check.
        sg_ip_rule (str): The security group IP rule.

    Returns:
        bool: True if the IP is allowed, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        sg_ip_pieces = str(sg_ip_rule).replace(';', ',').replace(' ', '').split(',')
        logging.debug(f"Comparing IP {ip} with SG rule {sg_ip_rule} and IP object: {ip_obj} and SG IP pieces: {sg_ip_pieces}")
        for piece in sg_ip_pieces:
            if '/' in piece:
                if ip_obj in ipaddress.ip_network(piece, strict=False):
                    return True
            elif piece:
                if ip_obj == ipaddress.ip_address(piece):
                    return True
        return False
    except Exception as e:
        logging.warning(f"Could not parse IP rule: {sg_ip_rule} - {e}")
        return False

def find_non_matching_entries(new_df, sg_inbound_df, sg_outbound_df):
    """
    Finds entries in the traffic data that do not match any security group rule.

    Args:
        new_df (pd.DataFrame): The DataFrame containing the combined traffic data.
        sg_inbound_df (pd.DataFrame): The DataFrame containing inbound security group rules.
        sg_outbound_df (pd.DataFrame): The DataFrame containing outbound security group rules.

    Returns:
        pd.DataFrame: A DataFrame containing the unmatched entries.
    """
    unmatched = []
    for _, new_row in new_df.iterrows():
        row_type = new_row['type'].lower()
        if row_type == 'inbound':
            src_ip = new_row['sourceIp']
            dst_port = new_row['destinationPort']
            protocol = new_row['transportProtocol']
            sg_df = sg_inbound_df
        elif row_type == 'outbound':
            src_ip = new_row['destinationIp']
            dst_port = new_row['destinationPort']
            protocol = new_row['transportProtocol']
            sg_df = sg_outbound_df
        else:
            continue
        
        match_found = False
        for _, sg_row in sg_df.iterrows():
            if row_type == 'inbound':
                sg_ip = sg_row['Source']
            elif row_type == 'outbound':
                sg_ip = sg_row['Destination']
            sg_port = sg_row['Port range']
            sg_protocol_rule = sg_row['Protocol']
            
            logging.debug(f"Checking {row_type} - Src IP: {src_ip}, Dst Port: {dst_port} against SG IP: {sg_ip}, SG Port: {sg_port}")
            if ip_in_sg_rule_ip(src_ip, sg_ip) and \
               port_in_sg_rules(dst_port, sg_port) and \
               protocol_in_sg_rules(protocol, sg_protocol_rule):
                match_found = True
                break
        
        if not match_found:
            if row_type == 'inbound':
                unmatched.append({
                    'type': row_type, 
                    'sourceIp': src_ip, 
                    'destinationIp': new_row['destinationIp'], 
                    'destinationPort': dst_port, 
                    'transportProtocol': protocol
                })
            elif row_type == 'outbound':
                unmatched.append({
                    'type': row_type, 
                    'sourceIp': new_row['sourceIp'], 
                    'destinationIp': src_ip, 
                    'destinationPort': dst_port, 
                    'transportProtocol': protocol
                })
    return pd.DataFrame(unmatched)

def main():
    """
    Main function to parse arguments and run the IP analysis.
    """
    parser = argparse.ArgumentParser(description="Analyze IP traffic and compare with security group rules.")
    parser.add_argument("--os-type", required=True, help="Operating system type (e.g., Windows, Linux, MacOS)")
    parser.add_argument("--env-type", required=True, help="Environment type (e.g., Dev, Prod)")
    parser.add_argument("--inbound-file", default="destinationProcessConnection.csv", help="Path to the inbound traffic CSV file")
    parser.add_argument("--outbound-file", default="sourceProcessConnection.csv", help="Path to the outbound traffic CSV file")
    parser.add_argument("--sg-file", default="SG Rules.xlsx", help="Path to the security group rules Excel file")
    parser.add_argument("--output-file", default="combined_inbound_outbound.xlsx", help="Path to the output Excel file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    inbound_df = read_and_process_csv(args.inbound_file, args.os_type, args.env_type, 'inbound')
    outbound_df = read_and_process_csv(args.outbound_file, args.os_type, args.env_type, 'outbound')

    final_df = combine_dataframes(inbound_df, outbound_df)
    
    write_to_excel(final_df, args.output_file, 'Inbound and Outbound')

    new_df = pd.read_excel(args.output_file, sheet_name='Inbound and Outbound')
    
    sg_inbound_df, sg_outbound_df = read_sg_rules(args.sg_file, args.os_type, args.env_type)

    unmatched_df = find_non_matching_entries(new_df, sg_inbound_df, sg_outbound_df)

    if not unmatched_df.empty:
        logging.info("Unmatched records found:")
        append_to_excel(unmatched_df, args.output_file, 'Unmatched')
    else:
        logging.info("All records are covered by SG rules.")

if __name__ == "__main__":
    main()
