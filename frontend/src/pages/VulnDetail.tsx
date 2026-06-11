import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box, Typography, Card, CardContent, Chip, Button, Stack,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Alert, Snackbar, Link,
} from '@mui/material';
import {
  BugReport as BugIcon, OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchVulnerability, fetchPatches } from '../api/scans';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import DiffViewer from '../components/DiffViewer';

const VulnDetail: React.FC = () => {
  const { scanId, vulnId } = useParams<{ scanId: string; vulnId: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const { data: vuln } = useQuery({
    queryKey: ['vuln', vulnId],
    queryFn: () => fetchVulnerability(scanId!, vulnId!),
    enabled: !!scanId && !!vulnId,
  });
  const { data: patches } = useQuery({
    queryKey: ['patches', vulnId],
    queryFn: () => fetchPatches(scanId!, vulnId!),
    enabled: !!scanId && !!vulnId,
  });

  // GitHub single issue dialog
  const [issueDialogOpen, setIssueDialogOpen] = useState(false);
  const [issueRepo, setIssueRepo] = useState('');
  const [issueLoading, setIssueLoading] = useState(false);
  const [issueResult, setIssueResult] = useState<{ url?: string; number?: number; error?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!vuln) return <Typography>{t('common.loading')}</Typography>;

  const handleCreateSingleIssue = async () => {
    setIssueLoading(true);
    setError(null);
    setIssueResult(null);
    try {
      // Reuse the multi-issue endpoint with a single vuln filtered approach,
      // but the backend endpoint creates issues for ALL vulns in a scan.
      // Instead, we create issues for all and filter later, OR we just
      // call the same endpoint. The better approach: create issues for all,
      // the user can see which one corresponds.
      // Actually, let's just use the scan-level endpoint directly.
      const { data } = await api.post(`/scans/${scanId}/issues`, {
        repo: issueRepo || undefined,
      });
      // Find the result matching this vuln
      const result = (data.results || []).find((r: any) => r.vuln_id === vulnId);
      setIssueResult(result || { error: 'No result returned for this vulnerability' });
      setIssueDialogOpen(false);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || 'Failed to create issue');
    } finally {
      setIssueLoading(false);
    }
  };

  // Guess repo from scan context if available via the scan fetch
  React.useEffect(() => {
    if (scanId) {
      api.get(`/scans/${scanId}`).then(res => {
        const path = res.data?.source_path || '';
        if (path.includes('github.com')) {
          setIssueRepo(path.replace(/\.git$/, ''));
        }
      }).catch(() => {});
    }
  }, [scanId]);

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto' }}>
      {/* Back button */}
      <Button sx={{ mb: 2 }} onClick={() => navigate(`/scans/${scanId}`)}>
        &larr; {t('common.back')}
      </Button>

      {/* ── Vulnerability Info ── */}
      <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mb: 3 }}>
        <CardContent>
          <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
            <SeverityBadge severity={vuln.severity} />
            {vuln.cwe_id && <Chip label={vuln.cwe_id} size="small" variant="outlined" />}
          </Stack>
          <Typography variant="h5" fontWeight={600} sx={{ mb: 2 }}>
            {vuln.title}
          </Typography>
          <Typography color="text.secondary">
            {t('vuln.file')}: <strong>{vuln.file_path}</strong>
            {vuln.line_start && (
              <> | {t('vuln.line')}: <strong>{vuln.line_start}{vuln.line_end ? `-${vuln.line_end}` : ''}</strong></>
            )}
          </Typography>
          {vuln.description && (
            <Typography sx={{ mt: 2 }}>{vuln.description}</Typography>
          )}

          {/* GitHub Issue Button */}
          <Box sx={{ mt: 2 }}>
            <Button
              variant="outlined"
              size="small"
              startIcon={<BugIcon />}
              onClick={() => setIssueDialogOpen(true)}
            >
              {t('github.createIssue')}
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* ── Vulnerable Code ── */}
      {vuln.vulnerable_code && (
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
              Vulnerable Code
            </Typography>
            <Box
              component="pre"
              sx={{
                p: 2, bgcolor: 'grey.100', borderRadius: 1,
                overflow: 'auto', fontSize: 13, fontFamily: 'monospace',
              }}
            >
              {vuln.vulnerable_code}
            </Box>
          </CardContent>
        </Card>
      )}

      {/* ── Fix Patch ── */}
      {patches && patches.length > 0 && (
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
              {t('vuln.fix')}
            </Typography>
            {patches.map(p => (
              <Box key={p.id}>
                <DiffViewer diff={p.diff_content || ''} />
                <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
                  <Button variant="contained" size="small">{t('vuln.apply')}</Button>
                </Box>
              </Box>
            ))}
          </CardContent>
        </Card>
      )}

      {/* ── Single Issue Dialog ── */}
      <Dialog
        open={issueDialogOpen}
        onClose={() => !issueLoading && setIssueDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{t('github.createIssue')}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              fullWidth
              label={t('github.repo')}
              value={issueRepo}
              onChange={e => setIssueRepo(e.target.value)}
              helperText={t('github.repoHint')}
              size="small"
              placeholder="owner/repo"
            />
            <Alert severity="info" sx={{ fontSize: 13 }}>
              This will create a GitHub Issue for <strong>{vuln.title}</strong>
              {vuln.cwe_id && <> ({vuln.cwe_id})</>}
            </Alert>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIssueDialogOpen(false)} disabled={issueLoading}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleCreateSingleIssue}
            disabled={issueLoading || !issueRepo.trim()}
          >
            {issueLoading ? t('github.creating') : t('github.createIssue')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Issue Result Display ── */}
      {issueResult && (
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mt: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 1 }}>
              {t('github.results')}
            </Typography>
            {issueResult.url ? (
              <Link href={issueResult.url} target="_blank" rel="noopener" underline="hover" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Chip
                  label={t('github.issueCreated', { number: issueResult.number })}
                  size="small" color="success"
                />
                <OpenInNewIcon fontSize="small" />
              </Link>
            ) : (
              <Alert severity="error">{issueResult.error}</Alert>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Error Snackbar ── */}
      <Snackbar
        open={!!error}
        autoHideDuration={5000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert severity="error" onClose={() => setError(null)} variant="filled">
          {error}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default VulnDetail;
