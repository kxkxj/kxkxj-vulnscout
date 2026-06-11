import React, { useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  CardContent,
  CardActions,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  Snackbar,
  Collapse,
} from '@mui/material';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchScan, fetchResults, createPullRequest } from '../api/scans';
import SeverityBadge from '../components/SeverityBadge';
import type { Vulnerability, FixGroup } from '../types';

const ScanResult: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const [prDialogOpen, setPrDialogOpen] = useState(false);
  const [branchName, setBranchName] = useState('vulnscout-fix');
  const [baseBranch, setBaseBranch] = useState('main');
  const [successAlert, setSuccessAlert] = useState<string | null>(null);

  const { data: scan } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => fetchScan(scanId!),
    enabled: !!scanId,
  });

  const { data: vulns } = useQuery({
    queryKey: ['results', scanId],
    queryFn: () => fetchResults(scanId!),
    enabled: !!scanId,
  });

  const fixGroups = useMemo<FixGroup[]>(() => {
    if (!vulns) return [];
    const map = new Map<string, Vulnerability[]>();
    vulns.forEach((v) => {
      const path = v.file_path || 'unknown';
      if (!map.has(path)) map.set(path, []);
      map.get(path)!.push(v);
    });
    return Array.from(map.entries()).map(([filePath, fileVulns]) => ({
      file_path: filePath,
      vulns: fileVulns,
    }));
  }, [vulns]);

  const prMutation = useMutation({
    mutationFn: () =>
      createPullRequest(scanId!, scan?.source_path, branchName, baseBranch),
    onSuccess: (data) => {
      setPrDialogOpen(false);
      setSuccessAlert(data.pr_url);
    },
  });

  const totalFiles = fixGroups.length;
  const isDone = scan?.status === 'done';
  const isUrl = scan?.source_type === 'url';

  if (!scan || !vulns) {
    return <Typography>{t('common.loading')}</Typography>;
  }

  return (
    <Box>
      {/* Success Snackbar */}
      <Snackbar
        open={!!successAlert}
        autoHideDuration={10000}
        onClose={() => setSuccessAlert(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert
          severity="success"
          onClose={() => setSuccessAlert(null)}
          sx={{ width: '100%' }}
        >
          {t('scan.prCreated')}{' '}
          <a
            href={successAlert!}
            target="_blank"
            rel="noopener noreferrer"
          >
            {successAlert}
          </a>
        </Alert>
      </Snackbar>

      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h4" fontWeight={600}>
            {t('scan.results')}
          </Typography>
          <Typography color="text.secondary">
            {scan.source_path} — {scan.scanned_files}/{scan.total_files} files
          </Typography>
        </Box>
        <Chip
          label={scan.status}
          color={scan.status === 'done' ? 'success' : scan.status === 'failed' ? 'error' : 'default'}
        />
      </Box>

      {/* Vulnerabilities list */}
      <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
            {scan.vuln_count_critical > 0 && (
              <Box><SeverityBadge severity="critical" /> <strong>{scan.vuln_count_critical}</strong></Box>
            )}
            {scan.vuln_count_high > 0 && (
              <Box><SeverityBadge severity="high" /> <strong>{scan.vuln_count_high}</strong></Box>
            )}
            {scan.vuln_count_medium > 0 && (
              <Box><SeverityBadge severity="medium" /> <strong>{scan.vuln_count_medium}</strong></Box>
            )}
            {scan.vuln_count_low > 0 && (
              <Box><SeverityBadge severity="low" /> <strong>{scan.vuln_count_low}</strong></Box>
            )}
          </Box>

          <List disablePadding>
            {vulns.map((vuln) => (
              <ListItem key={vuln.id} disablePadding>
                <ListItemButton
                  onClick={() => navigate(`/scans/${scanId}/vulns/${vuln.id}`)}
                >
                  <SeverityBadge severity={vuln.severity} />
                  <ListItemText
                    sx={{ ml: 2 }}
                    primary={vuln.title}
                    secondary={`${vuln.file_path}:${vuln.line_start || '?'}`}
                  />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>

      {/* Fix Suggestions card — only when scan is done */}
      {isDone && (
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 1 }}>
              {t('scan.fixSummary')}
            </Typography>
            <Typography color="text.secondary" sx={{ mb: 2 }}>
              {fixGroups.length > 0
                ? t('scan.totalFixes', { count: vulns.length, files: totalFiles })
                : t('scan.noFixes')}
            </Typography>

            {fixGroups.length > 0 && (
              <List disablePadding>
                {fixGroups.map((group) => (
                  <Collapse key={group.file_path} in>
                    <ListItem disablePadding sx={{ flexDirection: 'column', alignItems: 'stretch' }}>
                      <ListItemText
                        primary={
                          <Typography
                            variant="body2"
                            fontFamily="monospace"
                            fontWeight={600}
                            sx={{ mb: 0.5 }}
                          >
                            {group.file_path}
                          </Typography>
                        }
                        secondary={`${group.vulns.length} ${group.vulns.length > 1 ? 'vulnerabilities' : 'vulnerability'}`}
                        sx={{ px: 2, py: 1, bgcolor: 'action.hover', borderRadius: 1 }}
                      />
                      <List disablePadding sx={{ pl: 2 }}>
                        {group.vulns.map((vuln) => (
                          <ListItem key={vuln.id} disablePadding>
                            <ListItemButton
                              dense
                              onClick={() => navigate(`/scans/${scanId}/vulns/${vuln.id}`)}
                            >
                              <SeverityBadge severity={vuln.severity} />
                              <ListItemText
                                sx={{ ml: 1.5 }}
                                primary={vuln.title}
                                secondary={`L${vuln.line_start || '?'}`}
                                primaryTypographyProps={{ variant: 'body2' }}
                                secondaryTypographyProps={{ variant: 'caption' }}
                              />
                            </ListItemButton>
                          </ListItem>
                        ))}
                      </List>
                    </ListItem>
                  </Collapse>
                ))}
              </List>
            )}
          </CardContent>

          {/* Create PR button — only for GitHub URL scans */}
          {isUrl && fixGroups.length > 0 && (
            <CardActions sx={{ px: 2, pb: 2 }}>
              <Button
                variant="contained"
                color="primary"
                fullWidth
                onClick={() => {
                  setBranchName('vulnscout-fix');
                  setBaseBranch('main');
                  setPrDialogOpen(true);
                }}
              >
                {t('scan.createPR')}
              </Button>
            </CardActions>
          )}
        </Card>
      )}

      {/* Create PR Dialog */}
      <Dialog
        open={prDialogOpen}
        onClose={() => setPrDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{t('scan.prDialogTitle')}</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
            <TextField
              label={t('scan.githubUrl')}
              value={scan.source_path}
              size="small"
              InputProps={{ readOnly: true }}
            />
            <TextField
              label={t('scan.branchName')}
              value={branchName}
              size="small"
              onChange={(e) => setBranchName(e.target.value)}
            />
            <TextField
              label={t('scan.baseBranch')}
              value={baseBranch}
              size="small"
              onChange={(e) => setBaseBranch(e.target.value)}
            />
            <Alert severity="info">
              {t('scan.totalFixes', { count: vulns.length, files: totalFiles })}
            </Alert>
            {prMutation.isError && (
              <Alert severity="error">
                {t('scan.prFailed')}: {(prMutation.error as Error).message}
              </Alert>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPrDialogOpen(false)}>{t('scan.cancel')}</Button>
          <Button
            variant="contained"
            onClick={() => prMutation.mutate()}
            disabled={prMutation.isPending}
          >
            {prMutation.isPending ? t('common.loading') : t('scan.confirmCreate')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ScanResult;
