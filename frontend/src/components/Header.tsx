import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  AppBar, Toolbar, Typography, Button, Box, ToggleButton, ToggleButtonGroup,
  Select, MenuItem, Chip, FormControl, Tooltip, CircularProgress, Snackbar, Alert,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';

interface ModelEntry {
  name: string;
  size_gb: number;
  description: string;
  provider: string;
  downloaded?: boolean;
}

interface ModelInfo {
  current: { provider: string; model: string; api_url: string };
  local: ModelEntry[];
  cloud: ModelEntry[];
  downloadable: ModelEntry[];
  recommended: string;
  ollama_running: boolean;
  ollama_installed: boolean;
  cloud_configured: boolean;
}

const POLL_INTERVAL_MS = 15000; // Refresh model list every 15s

const Header: React.FC = () => {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const fetchModels = useCallback(async () => {
    try {
      const res = await api.get<ModelInfo>('/models');
      if (mountedRef.current) {
        setModelInfo(res.data);
      }
    } catch {
      // Silently retry on next poll
    }
  }, []);

  // Initial fetch + periodic refresh
  useEffect(() => {
    mountedRef.current = true;
    fetchModels();
    const interval = setInterval(fetchModels, POLL_INTERVAL_MS);
    return () => {
      mountedRef.current = false;
      clearInterval(interval);
    };
  }, [fetchModels]);

  const handleModelChange = async (modelName: string) => {
    if (modelName === modelInfo?.current.model) return;
    setSwitching(true);
    setError(null);
    try {
      await api.post('/models/switch', { model_name: modelName });
      // Immediately refresh to get updated state
      await fetchModels();
    } catch (e: any) {
      const msg = e?.response?.data?.detail || e?.message || 'Failed to switch model';
      setError(msg);
    } finally {
      setSwitching(false);
    }
  };

  // ---- Build the dropdown options ----
  const renderOptions = () => {
    if (!modelInfo) return null;

    const options: React.ReactNode[] = [];
    const currentModel = modelInfo.current.model;
    const hasLocal = modelInfo.local.length > 0;
    const hasCloud = modelInfo.cloud.length > 0;

    // --- Local models (downloaded) ---
    if (hasLocal) {
      options.push(
        <MenuItem key="__local_header" disabled sx={{ opacity: 0.6, fontSize: 11 }}>
          — Local (Ollama) {modelInfo.ollama_running ? '' : '⏸'} —
        </MenuItem>
      );
      modelInfo.local.forEach((m) => {
        const isCurrent = m.name === currentModel;
        options.push(
          <MenuItem key={m.name} value={m.name} sx={{ fontSize: 13 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, width: '100%' }}>
              {m.name}
              <Chip label="ready" size="small" color="success" sx={{ height: 18, fontSize: 10 }} />
              {isCurrent && <Chip label="active" size="small" color="primary" sx={{ height: 18, fontSize: 10 }} />}
            </Box>
          </MenuItem>
        );
      });
    }

    // --- Downloadable models (in Ollama but not pulled yet) ---
    if (modelInfo.ollama_running && modelInfo.downloadable.length > 0) {
      options.push(
        <MenuItem key="__downloadable_header" disabled sx={{ opacity: 0.6, fontSize: 11 }}>
          — Available to Download —
        </MenuItem>
      );
      modelInfo.downloadable.forEach((m) => {
        options.push(
          <MenuItem key={`dl_${m.name}`} value={m.name} sx={{ fontSize: 13 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, width: '100%' }}>
              {m.name}
              <Chip
                label={`${m.size_gb}GB · pull needed`}
                size="small"
                variant="outlined"
                color="warning"
                sx={{ height: 18, fontSize: 9 }}
              />
            </Box>
          </MenuItem>
        );
      });
    }

    // --- Cloud models ---
    if (hasCloud) {
      options.push(
        <MenuItem key="__cloud_header" disabled sx={{ opacity: 0.6, fontSize: 11 }}>
          — Cloud API —
        </MenuItem>
      );
      modelInfo.cloud.forEach((m) => {
        const isCurrent = m.name === currentModel;
        options.push(
          <MenuItem key={m.name} value={m.name} sx={{ fontSize: 13 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, width: '100%' }}>
              {m.name}
              <Chip label="cloud" size="small" color="info" sx={{ height: 18, fontSize: 10 }} />
              {isCurrent && <Chip label="active" size="small" color="primary" sx={{ height: 18, fontSize: 10 }} />}
            </Box>
          </MenuItem>
        );
      });
    }

    // Fallback if nothing is available
    if (!hasLocal && !hasCloud && !modelInfo.ollama_running) {
      options.push(
        <MenuItem key="__no_models" disabled sx={{ opacity: 0.5, fontSize: 12 }}>
          {modelInfo.ollama_installed ? 'Ollama not running' : 'Ollama not installed'}
        </MenuItem>
      );
    }

    return options;
  };

  return (
    <AppBar position="static" elevation={0}>
      <Toolbar>
        <Typography
          variant="h6"
          component="div"
          sx={{ cursor: 'pointer', fontWeight: 700 }}
          onClick={() => navigate('/')}
        >
          {t('app.title')}
        </Typography>
        <Typography variant="body2" sx={{ ml: 1, opacity: 0.7 }}>
          {t('app.subtitle')}
        </Typography>

        <Box sx={{ ml: 4, display: 'flex', gap: 1 }}>
          <Button color="inherit" onClick={() => navigate('/')}>
            {t('nav.dashboard')}
          </Button>
          <Button color="inherit" onClick={() => navigate('/new-scan')}>
            {t('nav.newScan')}
          </Button>
        </Box>

        <Box sx={{ flexGrow: 1 }} />

        {/* Model Selector */}
        {modelInfo && (
          <FormControl size="small" sx={{ minWidth: 220, mr: 2 }}>
            <Select
              value={modelInfo.current.model}
              onChange={(e) => handleModelChange(e.target.value)}
              disabled={switching}
              renderValue={(value) => (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  {switching && <CircularProgress size={12} color="inherit" sx={{ mr: 0.5 }} />}
                  <Typography variant="body2" noWrap sx={{ fontSize: 13 }}>
                    {value}
                    {modelInfo.current.provider === 'openai' && ' ☁️'}
                    {modelInfo.current.provider === 'ollama' && ' 🖥'}
                  </Typography>
                </Box>
              )}
              sx={{
                color: 'white',
                '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.3)' },
                '& .MuiSvgIcon-root': { color: 'white' },
                fontSize: 13,
              }}
            >
              {renderOptions()}
            </Select>
          </FormControl>
        )}

        {/* Connection status indicator */}
        {modelInfo && (
          <Tooltip
            title={
              modelInfo.ollama_running
                ? 'Ollama connected'
                : modelInfo.ollama_installed
                  ? 'Ollama not running'
                  : 'Ollama not installed'
            }
          >
            <Box
              sx={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                mr: 2,
                bgcolor: modelInfo.ollama_running ? '#4caf50' : modelInfo.ollama_installed ? '#ff9800' : '#f44336',
              }}
            />
          </Tooltip>
        )}

        <ToggleButtonGroup
          value={i18n.language?.startsWith('zh') ? 'zh' : 'en'}
          exclusive
          onChange={(_, v) => v && i18n.changeLanguage(v)}
          size="small"
          sx={{
            '& .MuiToggleButton-root': {
              color: 'white',
              borderColor: 'rgba(255,255,255,0.3)',
              '&.Mui-selected': { color: 'white', bgcolor: 'rgba(255,255,255,0.15)' },
            },
          }}
        >
          <ToggleButton value="en">EN</ToggleButton>
          <ToggleButton value="zh">中</ToggleButton>
        </ToggleButtonGroup>
      </Toolbar>

      {/* Error snackbar */}
      <Snackbar
        open={!!error}
        autoHideDuration={4000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert severity="error" onClose={() => setError(null)} variant="filled">
          {error}
        </Alert>
      </Snackbar>
    </AppBar>
  );
};

export default Header;
