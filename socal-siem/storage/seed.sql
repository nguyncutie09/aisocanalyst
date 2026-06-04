-- ============================================================
-- SOCal SIEM - Seed Data
-- MITRE ATT&CK techniques, demo inventory, sample data
-- ============================================================

-- MITRE ATT&CK Techniques (Core subset)
INSERT INTO mitre_attack (id, type, name, description, matrix) VALUES
('T1110', 'technique', 'Brute Force', 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.', 'enterprise'),
('T1078', 'technique', 'Valid Accounts', 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.', 'enterprise'),
('T1021', 'technique', 'Remote Services', 'Adversaries may use valid accounts to log into a service that accepts remote connections, such as SSH, RDP, or SMB.', 'enterprise'),
('T1548', 'technique', 'Abuse Elevation Control Mechanism', 'Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.', 'enterprise'),
('T1059', 'technique', 'Command and Scripting Interpreter', 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.', 'enterprise'),
('T1204', 'technique', 'User Execution', 'An adversary may rely upon a user to execute a malicious payload for them.', 'enterprise'),
('T1071', 'technique', 'Application Layer Protocol', 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.', 'enterprise'),
('T1560', 'technique', 'Archive Collected Data', 'An adversary may compress and/or encrypt data collected prior to exfiltration.', 'enterprise'),
('T1190', 'technique', 'Exploit Public-Facing Application', 'Adversaries may attempt to exploit a weakness in an Internet-facing computer or program.', 'enterprise'),
('T1098', 'technique', 'Account Manipulation', 'Adversaries may manipulate accounts to maintain access to victim systems.', 'enterprise')
ON CONFLICT (id) DO NOTHING;

-- MITRE ATT&CK Tactics
INSERT INTO mitre_attack (id, type, name, description) VALUES
('TA0001', 'tactic', 'Initial Access', 'The adversary is trying to get into your network.'),
('TA0002', 'tactic', 'Execution', 'The adversary is trying to run malicious code.'),
('TA0003', 'tactic', 'Persistence', 'The adversary is trying to maintain their foothold.'),
('TA0004', 'tactic', 'Privilege Escalation', 'The adversary is trying to gain higher-level permissions.'),
('TA0005', 'tactic', 'Defense Evasion', 'The adversary is trying to avoid being detected.'),
('TA0006', 'tactic', 'Credential Access', 'The adversary is trying to steal account names and passwords.'),
('TA0007', 'tactic', 'Discovery', 'The adversary is trying to figure out your environment.'),
('TA0008', 'tactic', 'Lateral Movement', 'The adversary is trying to move through your environment.'),
('TA0009', 'tactic', 'Collection', 'The adversary is trying to gather data of interest.'),
('TA0011', 'tactic', 'Command and Control', 'The adversary is trying to communicate with compromised systems.')
ON CONFLICT (id) DO NOTHING;

-- Demo inventory
INSERT INTO inventory (hostname, ip, os, criticality, services) VALUES
('server1', '10.0.0.5', 'Linux Ubuntu 22.04', 'high', '["ssh", "nginx", "postgresql"]'),
('server2', '10.0.0.6', 'Linux Ubuntu 22.04', 'high', '["ssh", "apache", "mysql"]'),
('workstation1', '10.0.0.50', 'Windows 11', 'medium', '["rdp", "smb"]'),
('workstation2', '10.0.0.51', 'Windows 11', 'medium', '["rdp", "smb"]'),
('dns-server', '10.0.0.10', 'Linux Ubuntu 22.04', 'critical', '["dns", "ssh"]'),
('mail-server', '10.0.0.20', 'Linux Ubuntu 22.04', 'high', '["smtp", "imap", "ssh"]')
ON CONFLICT (hostname) DO NOTHING;
