# AI 漏洞代码审计助手 (VulnScout)

**日期:** 2026-05-16
**状态:** 草案

## 概述

VulnScout 是一个基于本地部署 DeepSeek-Coder 的开源 AI 漏洞代码审计助手。它可以扫描用户上传的代码或 GitHub 仓库，自动分析漏洞和安全风险，并生成修复建议和 PR 级别的补丁代码。同时支持 Web UI 和 CLI 两种交互方式，并自动适配 GPU 资源。

## 目标语言（MVP）

- Python
- JavaScript / TypeScript
- Java
- C / C++

## 系统架构

### 整体架构

```
用户层: 浏览器 (Web UI) + 终端 (CLI)
                |
API 网关: FastAPI (REST + WebSocket)
                |
服务层:
  - 代码解析服务 (tree-sitter AST)
  - 模型推理 Worker (vLLM / llama.cpp)
  ��� 修复生成服务 (patch diff)
  - 报告生成服务 (markdown/HTML/SARIF)
  - Git 服务 (克隆 / 增量拉取)
                |
数据层: SQLite (SQLAlchemy + alembic)
```

### 扫描流水线

1. **代码获取** — ZIP 上传 / `git clone --depth 1` GitHub URL / CLI 路径直接引用
2. **语言检测 & 文件筛选** — libmagic / linguist 语言检测；按目标语言后缀过滤；可跳过测试文件
3. **代码分块** — Tree-sitter AST 解析，按函数/方法切割，携带上下文窗口
4. **并行推理** — Worker Pool 并发调用 DeepSeek-Coder；通过 WebSocket 流式推送结果
5. **去重 & 聚合** — 合并同文件/同行/同类型漏洞；基于 CWE 去重；按严重程度排序
6. **修复生成** — 对确认的漏洞二次调用模型；输出 unified diff 格式
7. **报告输出** — Web UI 交互式报告 / CLI SARIF/JSON/Markdown

### 漏洞检测策略（三级级联）

| 级别 | 方法 | 覆盖场景 |
|---|---|---|
| 1. 规则预过滤 | Tree-sitter 模式匹配 | 硬编码密钥、危险函数调用、不安全随机数 |
| 2. 零样本推理 | 直接代码 → 模型 → 漏洞 | 逻辑漏洞、业务逻辑缺陷 |
| 3. Few-shot 模板 | OWASP 样本 + 对应修复 | SQL注入、XSS、命令注入、路径遍历 |

**1 → 2 → 3 级联**：先用规则低成本筛出疑点，再送模型深度判断，节省 token 和 GPU 时间。

### 模型推理层

- **自动硬件探测** — 启动时执行 `nvidia-smi` / `torch.cuda`；无 GPU 自动回退 CPU 模式
- **自动模型选择** — 基于显存：≥24GB → 7B 量化，≥12GB → 3B，≥8GB → 1.5B，<8GB/CPU → ollama 外部
- **可插拔后端** — vLLM（GPU 高吞吐）、llama.cpp（GPU/CPU 轻量）、Transformers（GPU 调试）
- **自动下载** — 首次运行自动从 HuggingFace / ModelScope（国内镜像）下载，例如 `deepseek-coder-1.3b-instruct-q4_k_m.gguf`

## 技术栈

### 后端

| 模块 | 技术 | 选择理由 |
|---|---|---|
| Web 框架 | FastAPI | 异步原生、自动 OpenAPI、原生 WebSocket |
| 异步任务 | Celery + Redis（可选） | 大仓库分析不阻塞 API |
| 模型推理 | vLLM（主推）/ llama.cpp（回退） | GPU 最佳性能 / CPU 可跑 |
| 模型管理 | HuggingFace Hub / ModelScope | 自动下载 + 国内镜像 |
| 代码解析 | tree-sitter (py-tree-sitter) | 多语言 AST 解析，秒级完成 |
| Git 操作 | GitPython | 克隆、diff 生成 |
| 数据库 | SQLite (SQLAlchemy + alembic) | 单机部署零依赖 |
| 包管理 | PDM 或 Poetry | 现代 Python 打包 |
| 配置 | pydantic-settings | 类型安全的配置管理 |
| 国际化 | gettext / fastapi-babel | 中英双语 |

### 前端

| 模块 | 技术 |
|---|---|
| 构建引擎 | Vite + React 18 + TypeScript |
| UI 组件库 | MUI (Material UI) — 干净专业 |
| 代码编辑器 | Monaco Editor (diff 对比) |
| 状态管理 | Zustand |
| 路由 | React Router v6 |
| 国际化 | react-i18next |
| WebSocket | 原生 + 自动重连 |
| 图表 | Recharts |
| HTTP 客户端 | TanStack Query (React Query) |

### 部署

- **Docker Compose** — Web + API + Worker + Redis 一键启动
- **pip install** — CLI 独立分发
- **模型下载** — 首次运行自动拉取

## API 设计

### REST 接口

```
POST /api/v1/scans                    # 创建扫描（上传 ZIP / 仓库 URL）
GET  /api/v1/scans/{id}               # 获取扫描状态 & 摘要
GET  /api/v1/scans/{id}/results       # 获取漏洞列表（分页）
GET  /api/v1/scans/{id}/results/{vid} # 获取单漏洞详情 + 修复 diff
GET  /api/v1/scans/{id}/report        # 下载报告 (?format=json|markdown|sarif)

WS   /ws/v1/scans/{id}/progress       # 扫描进度流式推送

POST /api/v1/patches/{vid}/apply      # 应用修复（生成 patch 文件）
POST /api/v1/scans/{id}/pr            # 创建 GitHub PR（需 token）
```

### WebSocket 协议

```json
{"type": "progress",    "percent": 45, "current_file": "auth/login.py"}
{"type": "vuln_found",  "file": "auth/login.py", "severity": "high", "title": "SQL注入"}
{"type": "file_done",   "file": "auth/login.py", "vulns": 2}
{"type": "scan_done",   "total_vulns": 12, "duration": 34.5}
```

## 数据模型 (SQLite)

```python
Scan:
  id, status(pending/running/done/failed), source_type(local/url/cli)
  source_path, language, total_files, scanned_files
  vuln_count(critical/high/medium/low), created_at

Vulnerability:
  id, scan_id, file_path, line_start, line_end
  cwe_id, severity, confidence
  title, description, vulnerable_code
  created_at

Patch:
  id, vuln_id, diff_content, description
  status(draft/applied/rejected)
  applied_at

Project:
  id, name, repo_url, last_scan_id, created_at
```

## CLI 设计 (Click)

```bash
vulnscout scan ./my-project              # 扫描本地目录
vulnscout scan https://github.com/xxx/repo   # 扫描 GitHub 仓库
vulnscout scan ./file.zip                # 扫描 ZIP 文件

vulnscout scan . --format json           # JSON 输出
vulnscout scan . --format sarif          # SARIF 格式（兼容 GitHub CodeQL）
vulnscout scan . --output report.md      # 输出到文件

vulnscout config init                    # 生成 .vulnscout.yml
vulnscout config set model 7B            # 指定模型大小
vulnscout config set backend vllm        # 指定推理后端

vulnscout patch apply <vuln-id>          # 应用单个修复
vulnscout patch apply-all                # 应用所有修复
vulnscout scan . --auto-fix              # 扫描并自动生成补丁

vulnscout doctor                         # 诊断环境（GPU/模型/依赖）
vulnscout model download                 # 下载/切换模型
vulnscout model status                   # 查看当前模型状态
```

## Web UI 页面

| 页面 | 功能 |
|---|---|
| Dashboard | 扫描历史、项目列表、统计概览 |
| New Scan | ZIP 拖拽上传 / GitHub URL 输入 / 配置选项 |
| Scan Progress | 实时进度条 + 已发现漏洞流式展示 |
| Scan Result | 漏洞列表（按文件/严重度/CWE 筛选排序） |
| Vuln Detail | 代码上下文高亮 + 漏洞说明 + 修复 diff (Monaco diff editor) |
| Report | 可导出的报告视图（支持 print to PDF） |

### UI 设计原则

- 简洁专业，界面干净 — 不在任何地方使用表情符号
- 双语支持（中文 / 英文）— 顶部导航栏切换
- 清晰的信息层级 — 严重度颜色编码（Critical 红色 / High 橙色 / Medium 黄色 / Low 灰色）
- 响应式布局 — 桌面优先，适配移动端

## 项目目录结构

```
vulnscout/
├── pyproject.toml
├── docker-compose.yml
├── Dockerfile
│
├── vulnscout/
│   ├── __init__.py
│   ├── main.py                     # FastAPI 入口
│   ├── cli.py                      # Click CLI 入口
│   ├── api/
│   │   ├── scans.py
│   │   ├── patches.py
│   │   └── ws.py
│   ├── core/
│   │   ├── config.py
│   │   ├── i18n.py
│   │   ├── detector.py             # 硬件探测
│   │   └── model_manager.py
│   ├── scanner/
│   │   ├── pipeline.py
│   │   ├── code_fetcher.py
│   │   ├── language_detector.py
│   │   ├── chunker.py
│   │   ├── analyzer.py
│   │   ├── dedup.py
│   │   └── patch_generator.py
│   ├── models/
│   │   ├── db.py
│   │   └── schemas.py
│   └── utils/
│       ├── git_utils.py
│       └── report_formatter.py
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/
│   │   ├── components/
│   │   ├── i18n/
│   │   └── api/
│   ├── package.json
│   └── vite.config.ts
│
└── docs/
    ├── README.md
    ├── quickstart.md
    └── architecture.md
```

## 设计原则

- **YAGNI** — MVP 聚焦核心扫�� + 报告 + 修复，不包含用户认证/团队协作
- **模块化** — 每个服务单一职责，接口定义清晰
- **贡献者友好** — Python + TypeScript，低门槛参与
- **隔离性** — CLI 和 Web UI 共享 API 层，可独立测试和部署
- **优雅降级** — 无 GPU → CPU 模式；无模型 → 清楚错误提示 + 设置指南
