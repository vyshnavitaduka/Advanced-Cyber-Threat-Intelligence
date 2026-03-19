export interface MitreTactic {
  id: string;
  name: string;
  description: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tacticId: string;
  description: string;
}

export interface Alert {
  id: string;
  timestamp: string;
  message: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  iocValue: string;
  iocType: string;
  sourceLog?: string;
  relatedAlertIds?: string[];
  correlationScore?: number;
}

export interface Correlation {
  id: string;
  indicator: string;
  type: string;
  alerts: string[]; // IDs of related alerts
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  lastSeen: string;
  description: string;
}

export interface IOC {
  id: string;
  value: string;
  type: 'IP' | 'Domain' | 'Hash';
  tags: string[];
  addedAt: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
}

export interface Threat {
  id: string;
  timestamp: string;
  source: string;
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'Active' | 'Mitigated' | 'Investigating';
  location: {
    lat: number;
    lng: number;
    country: string;
  };
  description: string;
}

export interface ThreatMetric {
  name: string;
  value: number;
}

export interface TimelineData {
  time: string;
  threats: number;
}

export interface LogAnalysisResult {
  id: string;
  timestamp: string;
  fileName: string;
  entities: {
    ips: string[];
    urls: string[];
    timestamps: string[];
  };
  anomalies: {
    type: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    description: string;
    evidence: string[];
  }[];
  summary: string;
}

export interface Report {
  id: string;
  type: 'Threat Summary' | 'Incident Report';
  timestamp: string;
  generatedBy: string;
  summary: string;
  details: any;
}

export type UserRole = 'Admin' | 'Analyst';

export interface User {
  id: string;
  username: string;
  role: UserRole;
  email: string;
  lastLogin: string;
}
