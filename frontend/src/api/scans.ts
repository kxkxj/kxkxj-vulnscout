import api from './client';
import type { Scan, Vulnerability, Patch, PRResult } from '../types';

export const fetchScans = async (): Promise<Scan[]> => {
  const { data } = await api.get('/scans');
  return data;
};

export const fetchScan = async (id: string): Promise<Scan> => {
  const { data } = await api.get(`/scans/${id}`);
  return data;
};

export const fetchResults = async (
  scanId: string,
  severity?: string,
  filePath?: string,
): Promise<Vulnerability[]> => {
  const params: Record<string, string> = {};
  if (severity) params.severity = severity;
  if (filePath) params.file_path = filePath;
  const { data } = await api.get(`/scans/${scanId}/results`, { params });
  return data;
};

export const fetchVulnerability = async (
  scanId: string,
  vulnId: string,
): Promise<Vulnerability> => {
  const { data } = await api.get(`/scans/${scanId}/results/${vulnId}`);
  return data;
};

export const fetchPatches = async (
  scanId: string,
  vulnId: string,
): Promise<Patch[]> => {
  const { data } = await api.get(`/scans/${scanId}/results/${vulnId}/patches`);
  return data;
};

export const createScan = async (sourceType: string, sourcePath: string): Promise<Scan> => {
  const { data } = await api.post('/scans', null, {
    params: { source_type: sourceType, source_path: sourcePath },
  });
  return data;
};

export const createScanFromZip = async (file: File): Promise<Scan> => {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await api.post('/scans?source_type=local', formData);
  return data;
};

export const createPullRequest = async (
  scanId: string,
  repo?: string,
  branch?: string,
  base?: string,
): Promise<PRResult> => {
  const { data } = await api.post(`/scans/${scanId}/pr`, {
    repo: repo || undefined,
    branch: branch || 'vulnscout-fix',
    base: base || 'main',
  });
  return data;
};

export const applyPatch = async (patchId: string): Promise<void> => {
  await api.post(`/patches/${patchId}/apply`);
};

export const rejectPatch = async (patchId: string): Promise<void> => {
  await api.post(`/patches/${patchId}/reject`);
};
