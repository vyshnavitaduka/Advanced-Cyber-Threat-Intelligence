import { Threat, MitreTactic, MitreTechnique, IOC } from './types';

export const MITRE_TACTICS: MitreTactic[] = [
  { id: 'TA0001', name: 'Initial Access', description: 'The adversary is trying to get into your network.' },
  { id: 'TA0002', name: 'Execution', description: 'The adversary is trying to run malicious code.' },
  { id: 'TA0003', name: 'Persistence', description: 'The adversary is trying to maintain their foothold.' },
  { id: 'TA0004', name: 'Privilege Escalation', description: 'The adversary is trying to gain higher-level permissions.' },
  { id: 'TA0005', name: 'Defense Evasion', description: 'The adversary is trying to avoid being detected.' },
  { id: 'TA0006', name: 'Credential Access', description: 'The adversary is trying to steal account names and passwords.' },
  { id: 'TA0007', name: 'Discovery', description: 'The adversary is trying to figure out your environment.' },
  { id: 'TA0008', name: 'Lateral Movement', description: 'The adversary is trying to move through your environment.' },
  { id: 'TA0009', name: 'Collection', description: 'The adversary is trying to gather data of interest to their goal.' },
  { id: 'TA0011', name: 'Command and Control', description: 'The adversary is trying to communicate with compromised systems to control them.' },
  { id: 'TA0010', name: 'Exfiltration', description: 'The adversary is trying to steal data.' },
  { id: 'TA0040', name: 'Impact', description: 'The adversary is trying to manipulate, interrupt, or destroy your systems and data.' },
];

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  { id: 'T1566', tacticId: 'TA0001', name: 'Phishing', description: 'Adversaries may send phishing messages to gain access to victim systems.' },
  { id: 'T1059', tacticId: 'TA0002', name: 'Command and Scripting Interpreter', description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.' },
  { id: 'T1547', tacticId: 'TA0003', name: 'Boot or Logon Autostart Execution', description: 'Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence.' },
  { id: 'T1078', tacticId: 'TA0004', name: 'Valid Accounts', description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining privilege escalation.' },
  { id: 'T1027', tacticId: 'TA0005', name: 'Obfuscated Files or Information', description: 'Adversaries may attempt to make executable code or file content difficult to discover or analyze.' },
  { id: 'T1110', tacticId: 'TA0006', name: 'Brute Force', description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.' },
  { id: 'T1087', tacticId: 'TA0007', name: 'Account Discovery', description: 'Adversaries may attempt to get a listing of local system or domain accounts.' },
  { id: 'T1021', tacticId: 'TA0008', name: 'Remote Services', description: 'Adversaries may use valid accounts to log into a service that accepts remote connections.' },
  { id: 'T1005', tacticId: 'TA0009', name: 'Data from Local System', description: 'Adversaries may search local system sources, such as file systems and configuration files, to find data of interest.' },
  { id: 'T1071', tacticId: 'TA0011', name: 'Application Layer Protocol', description: 'Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.' },
  { id: 'T1041', tacticId: 'TA0010', name: 'Exfiltration Over C2 Channel', description: 'Adversaries may steal data by exfiltrating it over an existing command and control channel.' },
  { id: 'T1486', tacticId: 'TA0040', name: 'Data Encrypted for Impact', description: 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.' },
];

export const MOCK_IOCS: IOC[] = [
  {
    id: 'IOC-001',
    value: '185.220.101.5',
    type: 'IP',
    tags: ['tor', 'malware'],
    addedAt: new Date().toISOString(),
    description: 'Known Tor exit node associated with Cobalt Strike C2.',
    severity: 'High'
  },
  {
    id: 'IOC-002',
    value: 'update.microsoft-security.com',
    type: 'Domain',
    tags: ['phishing', 'apt28'],
    addedAt: new Date().toISOString(),
    description: 'Typosquatted domain used in credential harvesting campaign.',
    severity: 'Critical'
  },
  {
    id: 'IOC-003',
    value: '5e3504f4b25e77397e0278784d720c29',
    type: 'Hash',
    tags: ['ransomware', 'lockbit'],
    addedAt: new Date().toISOString(),
    description: 'MD5 hash of LockBit 3.0 encryptor payload.',
    severity: 'Critical'
  }
];

export const MOCK_THREATS: Threat[] = [
  {
    id: 'TR-9021',
    timestamp: new Date().toISOString(),
    source: '85.203.15.42',
    type: 'Brute Force',
    severity: 'High',
    status: 'Active',
    location: { lat: 55.7558, lng: 37.6173, country: 'Russia' },
    description: 'Multiple failed SSH login attempts detected on primary database server.'
  },
  {
    id: 'TR-9022',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    source: '103.45.12.11',
    type: 'Malware C2',
    severity: 'Critical',
    status: 'Investigating',
    location: { lat: 39.9042, lng: 116.4074, country: 'China' },
    description: 'Outbound traffic to known malicious command and control server.'
  },
  {
    id: 'TR-9023',
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    source: '192.168.1.105',
    type: 'Internal Lateral Movement',
    severity: 'Medium',
    status: 'Mitigated',
    location: { lat: 37.7749, lng: -122.4194, country: 'USA' },
    description: 'Suspicious internal scanning activity from workstation WS-04.'
  },
  {
    id: 'TR-9024',
    timestamp: new Date(Date.now() - 10800000).toISOString(),
    source: '45.12.4.99',
    type: 'DDoS',
    severity: 'High',
    status: 'Active',
    location: { lat: 52.5200, lng: 13.4050, country: 'Germany' },
    description: 'High volume of UDP traffic targeting edge load balancer.'
  }
];

export const MOCK_METRICS = [
  { name: 'Malware', value: 45 },
  { name: 'Phishing', value: 30 },
  { name: 'Brute Force', value: 15 },
  { name: 'DDoS', value: 10 },
];

export const MOCK_TIMELINE = [
  { time: '00:00', threats: 12 },
  { time: '04:00', threats: 18 },
  { time: '08:00', threats: 45 },
  { time: '12:00', threats: 32 },
  { time: '16:00', threats: 28 },
  { time: '20:00', threats: 15 },
];
