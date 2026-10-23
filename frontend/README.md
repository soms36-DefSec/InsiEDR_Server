# InsiEDR Security Operations Console (Frontend)

An enterprise-grade, high-performance React 19 + TypeScript + Vite Single-Page Application (SPA) providing real-time insider threat detection, host telemetry monitoring, AI/heuristic risk correlation, and an extensible plugin system.

---

## 1. Architectural Overview

The InsiEDR frontend is engineered for SOC tier-1 triage and tier-2 forensic investigation. It connects seamlessly to the Python FastAPI ASGI server via dual-channel telemetry:
1. **Server-Sent Events (SSE)** at `/api/v1/stream/sse` for low-latency reactive push updates.
2. **REST API Gateway** (`/api/*` and `/api/v1/*`) for deep queries, endpoint fleet status, user risk timelines, and forensic log pagination.

When built (`npm run build`), the compiled bundle in `frontend/dist/` is directly mounted and served at `/dashboard/` by FastAPI, providing a zero-external-dependency deployment.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        InsiEDR FastAPI ASGI Server                     │
│  ┌─────────────────────────┐  ┌───────────────┐  ┌───────────────────┐ │
│  │ /dashboard/ (Static SPA)│  │ /api/* (REST) │  │/api/v1/stream/sse │ │
│  └────────────┬────────────┘  └───────┬───────┘  └─────────┬─────────┘ │
└───────────────┼───────────────────────┼────────────────────┼───────────┘
                │                       │                    │
                ▼                       ▼                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         InsiEDR React 19 SPA                           │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │               useRealTimeStream (SSE + Adaptive Polling)       │   │
│   └───────┬───────────────────────────┬───────────────────┬────────┘   │
│           │                           │                   │            │
│           ▼                           ▼                   ▼            │
│   ┌───────────────┐           ┌───────────────┐   ┌────────────────┐   │
│   │   SOC View    │           │Telemetry View │   │  Plugins View  │   │
│   │ ───────────── │           │────────────── │   │ ────────────── │   │
│   │ - KpiGrid     │           │- FilterBar    │   │ - SocMatrix    │   │
│   │ - ChartsSection           │- Virtualized  │   │ - Explorer     │   │
│   │ - ThreatFeed  │           │  LogTable     │   │ - Custom Team  │   │
│   │ - FleetMatrix │           │- LogInspector │   │   Plugins      │   │
│   │ - DrillDown   │           │  Drawer       │   │                │   │
│   └───────────────┘           └───────────────┘   └────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Directory Structure

```
frontend/
├── src/
│   ├── components/
│   │   ├── soc/                  # Core SOC console widgets
│   │   │   ├── ChartsSection.tsx    # SVG timeline & score distribution charts
│   │   │   ├── DrillDownDrawer.tsx  # User forensic investigation drawer
│   │   │   ├── KpiGrid.tsx          # 7-card fleet executive KPI metrics
│   │   │   ├── ThreatFeed.tsx       # Live chronologically ordered threat stream
│   │   │   └── UserRiskTable.tsx    # Paginated, sortable endpoint fleet matrix
│   │   ├── telemetry/            # Raw log exploration & forensic tooling
│   │   │   ├── FilterBar.tsx        # Search, collector filter, and time range
│   │   │   ├── LogInspectorDrawer.tsx # Structured key/value & raw JSON viewer
│   │   │   └── VirtualizedLogTable.tsx# Windowed high-FPS DOM table (100k+ logs)
│   │   └── ui/                   # Reusable atomic design system
│   │       ├── Badge.tsx            # Severity & collector status badges
│   │       ├── Button.tsx           # Standardized interactive action buttons
│   │       ├── Card.tsx             # Structured surface cards
│   │       └── Drawer.tsx           # Accessible modal slide-over panels
│   ├── hooks/
│   │   └── useRealTimeStream.ts  # SSE connection manager + adaptive polling
│   ├── plugins/                  # Modular plugin registry & implementations
│   │   ├── registry.ts           # Central plugin metadata & event registry
│   │   ├── index.ts              # Plugin bootstrapping & exports
│   │   ├── template/             # Boilerplate reference template for developers
│   │   │   └── PluginTemplate.tsx
│   │   ├── soc-matrix/           # Built-in MITRE/CERT scenario matrix
│   │   │   └── SocMatrixPlugin.tsx
│   │   └── telemetry-explorer/   # Built-in deep forensic log explorer
│   │       └── TelemetryExplorerPlugin.tsx
│   ├── services/
│   │   └── api.ts                # Axios REST client & typed API contract functions
│   ├── types/
│   │   └── telemetry.ts          # Core domain TypeScript interfaces & models
│   ├── utils/
│   │   └── formatters.ts         # Risk scoring, time decay, date formatting
│   ├── App.tsx                   # Main SPA shell, navigation & tab controller
│   └── main.tsx                  # React 19 root bootstrap & strict mode
├── dist/                         # Compiled production bundle (served by FastAPI)
├── index.html                    # Root HTML entry point
├── package.json                  # Dependencies, scripts, and build metadata
├── tsconfig.json                 # TypeScript project configuration
└── vite.config.ts                # Vite build and dev-server configuration
```

---

## 3. Team Plugin Development Guide

The InsiEDR console includes a first-class plugin engine allowing team members to rapidly build and mount custom security tools, visualizations, SIEM integrations, or response playbooks without modifying core SOC components.

### Step 1: Create Your Plugin File
Create a new directory in `src/plugins/` (e.g., `src/plugins/my-feature/`) and create your component:

```tsx
// src/plugins/my-feature/MyFeaturePlugin.tsx
import React from 'react';
import type { InsiPlugin, PluginProps } from '../registry';
import { Card } from '../../components/ui/Card';
import { Activity } from 'lucide-react';

export const MyFeatureComponent: React.FC<PluginProps> = ({
  summary,
  agents,
  riskEvents,
  onDrillDown,
}) => {
  return (
    <Card title="Custom Security Tool" subtitle="Developed for internal SOC workflow">
      <div className="text-xs text-slate-600">
        Connected endpoints: {agents.length} | Logged threats: {riskEvents.length}
      </div>
      {/* Your custom interactive visualization or workflow here */}
    </Card>
  );
};

export const MyFeaturePlugin: InsiPlugin = {
  id: 'my-feature',
  title: 'Custom Security Tool',
  description: 'Team workflow extension for specialized threat hunting.',
  version: '1.0.0',
  author: 'Security Engineering Team',
  category: 'investigation',
  icon: Activity,
  component: MyFeatureComponent,
  defaultEnabled: true,
  permissions: ['read:telemetry', 'read:risk_scores'],
};
```

### Step 2: Register in `src/plugins/index.ts`
Open `src/plugins/index.ts` and register your new plugin:

```typescript
import { MyFeaturePlugin } from './my-feature/MyFeaturePlugin';

// Register built-in and team plugins
registerPlugin(SocMatrixPlugin);
registerPlugin(TelemetryExplorerPlugin);
registerPlugin(MyFeaturePlugin); // <-- Add your plugin here!
```

### Step 3: Test in the UI
Run `npm run dev` and navigate to the **Plugins** tab in the dashboard navigation bar. Your plugin will appear automatically in the plugin catalog and can be toggled on/off.

---

## 4. Reactive State & Telemetry Flow

The frontend state lifecycle is driven by `useRealTimeStream`:

1. **Initial Hydration**: On component mount, parallel REST requests fetch initial state from `/api/dashboard-summary`, `/api/events/risk-scores`, `/api/events/telemetry`, and `/api/endpoints`.
2. **Server-Sent Events (SSE)**: An `EventSource` connection is established to `/api/v1/stream/sse`.
   - When new telemetry or risk scoring events occur on the server, the backend pushes typed events (`heartbeat`, `telemetry`, `risk_score`).
   - The hook increments `streamCounter` and notifies all listening components without reloading the page.
3. **Adaptive Fallback Throttling**:
   - While SSE is connected (`isStreaming === true`), periodic background synchronization is throttled to **30 seconds** as a lightweight safety check.
   - If SSE disconnects, polling automatically accelerates to **3 seconds** to maintain real-time responsiveness until SSE reconnects.

---

## 5. Build, Run & Verification Commands

From the `frontend/` directory:

```bash
# 1. Install dependencies
npm install

# 2. Start Vite development server (with HMR)
npm run dev

# 3. Type-check and compile production bundle into dist/
npm run build

# 4. Run ESLint code inspection
npm run lint
```

When `npm run build` finishes, the FastAPI server (`server/asgi.py`) automatically serves the updated production bundle at:
`http://localhost:8000/dashboard/`

---

## 6. Key Domain Rules & Invariants

- **30-Minute Active Risk Window (`THREAT_DECAY_WINDOW_MS`)**:
  Assessments older than 30 minutes remain in history while active fleet posture returns to nominal until another elevated assessment arrives.
- **Risk Score Thresholds**:
  - `CRITICAL`: Score $\ge$ 90.0
  - `HIGH`: Score $\ge$ 70.0 and $<$ 90.0
  - `MEDIUM`: Score $\ge$ 40.0 and $<$ 70.0
  - `LOW`: Score $<$ 40.0
- **Log Virtualization**:
  The `VirtualizedLogTable` calculates exact row offsets and only renders visible DOM nodes + 6 overscan rows, ensuring high-speed rendering regardless of log dataset size.
