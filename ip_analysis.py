import pandas as pd
import ipaddress

os_type = input("Enter the OS type (e.g., Windows, Linux, MacOS): ")
env_type = input("Enter the Environment type (e.g., Dev, Prod): ")

cols_to_keep = [
    'sourceIp', 
    'sourcePort', 
    'destinationIp', 
    'destinationPort', 
    'transportProtocol'
]

# Read inbound file and create unique (sourceIp, destinationIp) pairs
inbound_df = pd.read_csv('destinationProcessConnection.csv', usecols=range(10))
inbound_df.columns = inbound_df.columns.str.strip()
inbound_df = inbound_df.drop_duplicates(subset=['sourceIp', 'destinationPort'])

inbound_df = inbound_df[inbound_df['destinationPort'] != 17472]

inbound_df = inbound_df[cols_to_keep]
inbound_df['OS'] = os_type
inbound_df['Environment'] = env_type
inbound_df['type'] = 'inbound'

# Read outbound file and create unique (sourceIp, destinationIp) pairs
outbound_df = pd.read_csv('sourceProcessConnection.csv', usecols=range(10))
outbound_df.columns = outbound_df.columns.str.strip()
print(outbound_df.columns)
outbound_df = outbound_df.drop_duplicates(subset=['destinationIp', 'destinationPort'])

outbound_df = outbound_df[outbound_df['destinationPort'] != 17472]

outbound_df = outbound_df[cols_to_keep]
outbound_df['OS'] = os_type
outbound_df['Environment'] = env_type
outbound_df['type'] = 'outbound'
print(outbound_df)
final_df = pd.concat([inbound_df, outbound_df], ignore_index=True)
# Write both DataFrames to separate sheets in a single Excel file
with pd.ExcelWriter('combined_inbound_outbound.xlsx') as writer:
    final_df.to_excel(writer, sheet_name='Inbound and Outbound', index=False)


new_df = pd.read_excel('combined_inbound_outbound.xlsx', sheet_name='Inbound and Outbound')

sg_file = 'SG Rules.xlsx'

os_sheet = os_type + '-' + env_type + '-' + 'Outbound'
sg_df = pd.read_excel(sg_file, sheet_name=os_sheet)


def protocol_in_sg_rules(protocol, sg_protocol_rule):
    """
    Check if protocol matches SG rule (which could be single, list, or 'ALL').
    """
    # Normalize input: case-insensitive & whitespace
    protocol = str(protocol).strip().upper()
    sg_rule = str(sg_protocol_rule).strip().upper()

    print(f"Comparing protocol {protocol} with SG rule {sg_rule}")

    if sg_rule == 'ALL':
        return True

    # Handle comma-separated lists (e.g., 'TCP,UDP,ICMP')
    if ',' in sg_rule:
        allowed_protocols = [proto.strip() for proto in sg_rule.split(',')]
        return protocol in allowed_protocols
    return protocol == sg_rule

def port_in_sg_rules(port, sg_port_rule):
    """Check if port matches SG rule (which could be single, range, or 'ALL')."""
    port = str(port)
    sg_rule = str(sg_port_rule).strip().upper()
    print(f"Comparing port {port} with SG rule {sg_rule}")
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
    """Check if IP is in SG rule subnet or matches SG rule IP (handles subnets)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Handle comma separated or multiline rules
        sg_ip_pieces = str(sg_ip_rule).replace(';', ',').replace(' ', '').split(',')
        print(f"Comparing IP {ip} with SG rule {sg_ip_rule} and IP object: {ip_obj} and SG IP pieces: {sg_ip_pieces}")
        for piece in sg_ip_pieces:
            if '/' in piece:
                print(ipaddress.ip_network(piece, strict=False))
                if ip_obj in ipaddress.ip_network(piece, strict=False):
                    return True
            elif piece:  # Ignore empty
                print(ipaddress.ip_address(piece))
                if ip_obj == ipaddress.ip_address(piece):
                    return True
        return False
    except Exception:
        return False

def find_non_matching_inbound_entries(new_df, sg_df):
    unmatched = []
    os_sheet_inbound = os_type + '-' + env_type + '-' + 'Inbound'
    os_sheet_outbound = os_type + '-' + env_type + '-' + 'Outbound'
    sg_inbound_df = pd.read_excel(sg_file, sheet_name=os_sheet_inbound)
    sg_outbound_df = pd.read_excel(sg_file, sheet_name=os_sheet_outbound)
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
        # Check if any SG rule matches both IP and port
        match_found = False
        for _, sg_row in sg_df.iterrows():
            if row_type == 'inbound':
                sg_ip = sg_row['Source']
            elif row_type == 'outbound':
                sg_ip = sg_row['Destination']
            sg_port = sg_row['Port range']
            sg_protocol_rule = sg_row['Protocol']
            print(f"Checking {row_type} - Src IP: {src_ip}, Dst Port: {dst_port} against SG IP: {sg_ip}, SG Port: {sg_port}")
            # Accept if both match, supporting subnet/ranges/ALL
            print(protocol_in_sg_rules(protocol, sg_protocol_rule))
            if ip_in_sg_rule_ip(src_ip, sg_ip) and port_in_sg_rules(dst_port, sg_port) and protocol_in_sg_rules(protocol, sg_protocol_rule):
                match_found = True
                break
            print("match_found", match_found)
        if not match_found:
            if row_type == 'inbound':
                unmatched.append({'type': row_type, 'sourceIp': src_ip, 'destinationIp': new_row['destinationIp'], 'destinationPort': dst_port, 'transportProtocol': protocol})
            elif row_type == 'outbound':
                unmatched.append({'type': row_type, 'sourceIp': new_row['sourceIp'], 'destinationIp': src_ip, 'destinationPort': dst_port, 'transportProtocol': protocol})
            else:
                continue
    return pd.DataFrame(unmatched)

unmatched_df = find_non_matching_inbound_entries(new_df, sg_df)

if not unmatched_df.empty:
    print("Inbound records NOT covered by SG rules:")
    with pd.ExcelWriter('combined_inbound_outbound.xlsx', engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
        unmatched_df.to_excel(writer, sheet_name='Unmatched', index=False)
else:
    print("All type records are covered by SG rules.")
 