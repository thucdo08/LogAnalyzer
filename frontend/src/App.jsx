import React, { useState, useMemo } from "react";
import { FileUpload } from "primereact/fileupload";
import "primereact/resources/themes/lara-light-blue/theme.css";
import "primereact/resources/primereact.min.css";
import "primeicons/primeicons.css";
import "./App.css";

const API_BASE = "https://api.thuandoandevops.site";

const SEVERITY_PRIORITY = {
  CRITICAL: 3,
  WARNING: 2,
  INFO: 1,
};

const getSeverityRank = (severity) => SEVERITY_PRIORITY[severity] || 0;

export default function App() {
  // dữ liệu
  const [status, setStatus] = useState("");
  const [preview, setPreview] = useState([]);

  const [resultsUp, setResultsUp] = useState([]);   // đã hậu xử lý
  const [summaryUp, setSummaryUp] = useState({});
  const [resultsRaw, setResultsRaw] = useState([]); // AI gốc
  const [summaryRaw, setSummaryRaw] = useState({});
  const [eventsPM, setEventsPM] = useState([]);

  // bổ sung hiển thị
  const [providerOpenAI, setProviderOpenAI] = useState(null); // true/false/null
  const [stats, setStats] = useState(null);                   // {raw_rows, shown_rows, dedup_dropped}
  const [validateReport, setValidateReport] = useState(null); // {ok, issues[], info{time_range, rows, columns}}

  // anomaly detection results
  const [anomalyReport, setAnomalyReport] = useState(null);     // step2_summary (raw anomalies)
  const [anomalyAnalyzed, setAnomalyAnalyzed] = useState(null); // step3_results (AI-analyzed)
  const [anomalySummary, setAnomalySummary] = useState(null);   // step4_summary
  const [anomalyStatus, setAnomalyStatus] = useState("");

  // điều khiển hiển thị
  const [viewMode, setViewMode] = useState("upgraded"); // 'upgraded' | 'raw' | 'anomalies'
  const [anomalyFilterLevel, setAnomalyFilterLevel] = useState(""); // lọc theo mức rủi ro
  const [anomalyFilterType, setAnomalyFilterType] = useState("");   // lọc theo loại bất thường
  const [query, setQuery] = useState("");

  // nhóm alerts theo "subject"
  const anomalySubjects = useMemo(() => {
    if (!Array.isArray(anomalyAnalyzed) || anomalyAnalyzed.length === 0) return [];

    const grouped = new Map();
    anomalyAnalyzed.forEach((alert) => {
      const subjectKey = alert?.subject || "(unknown)";
      if (!grouped.has(subjectKey)) {
        grouped.set(subjectKey, {
          subject: subjectKey,
          alerts: [],
          alertTypes: new Set(),
          maxSeverity: null,
          maxScore: null,
          ai_analysis: alert?.ai_analysis,
        });
      }

      const bucket = grouped.get(subjectKey);
      bucket.alerts.push(alert);

      const alertType = alert?.alert_type || alert?.type || "unknown";
      if (alertType) bucket.alertTypes.add(alertType);

      if (!bucket.ai_analysis && alert?.ai_analysis) {
        bucket.ai_analysis = alert.ai_analysis;
      }

      const severity = alert?.severity || "INFO";
      if (!bucket.maxSeverity || getSeverityRank(severity) > getSeverityRank(bucket.maxSeverity)) {
        bucket.maxSeverity = severity;
      }

      const score = typeof alert?.score === "number" ? alert.score : null;
      if (score != null && (bucket.maxScore == null || score > bucket.maxScore)) {
        bucket.maxScore = score;
      }
    });

    return Array.from(grouped.values()).map((bucket) => ({
      subject: bucket.subject,
      alerts: bucket.alerts,
      alertTypes: Array.from(bucket.alertTypes),
      alert_count: bucket.alerts.length,
      ai_analysis: bucket.ai_analysis,
      severity: bucket.maxSeverity,
      score: bucket.maxScore,
    }));
  }, [anomalyAnalyzed]);

  // danh sách type để render filter
  const anomalySubjectTypes = useMemo(() => {
    const types = new Set();
    anomalySubjects.forEach((subject) => {
      subject.alertTypes.forEach((t) => {
        if (t) types.add(t);
      });
    });
    return Array.from(types);
  }, [anomalySubjects]);

  const [selectedLevels, setSelectedLevels] = useState(
    new Set(["CRITICAL", "WARNING", "INFO"])
  );

  // áp dụng filter theo type + risk level + severity (CRITICAL/WARNING/INFO) + query search
  const filteredAnomalySubjects = useMemo(() => {
    let subjects = anomalySubjects;
    // Lọc theo alert type dropdown
    if (anomalyFilterType) {
      subjects = subjects.filter((subject) => subject.alertTypes.includes(anomalyFilterType));
    }
    // Lọc theo risk level dropdown
    if (anomalyFilterLevel) {
      subjects = subjects.filter((subject) => subject.ai_analysis?.risk_level === anomalyFilterLevel);
    }
    // Lọc theo severity checkbox (CRITICAL/WARNING/INFO)
    subjects = subjects.filter((subject) => {
      const sev = (subject.severity || "INFO").toUpperCase();
      return selectedLevels.has(sev);
    });
    // Lọc theo từ khóa tìm kiếm (query)
    const q = (query || "").toLowerCase().trim();
    if (q) {
      subjects = subjects.filter((subject) => {
        // Tìm trong subject name
        if (subject.subject?.toLowerCase().includes(q)) return true;
        // Tìm trong alert types
        if (subject.alertTypes.some((t) => t.toLowerCase().includes(q))) return true;
        // Tìm trong AI analysis summary
        if (subject.ai_analysis?.summary?.toLowerCase().includes(q)) return true;
        // Tìm trong risks
        if (subject.ai_analysis?.risks?.some((r) => r.toLowerCase().includes(q))) return true;
        // Tìm trong actions
        if (subject.ai_analysis?.actions?.some((a) => a.toLowerCase().includes(q))) return true;
        // Tìm trong alert text
        if (subject.alerts?.some((alert) => alert.text?.toLowerCase().includes(q))) return true;
        return false;
      });
    }
    return subjects;
  }, [anomalySubjects, anomalyFilterType, anomalyFilterLevel, selectedLevels, query]);

  const totalAnalyzedSubjects = anomalySubjects.length;
  const totalAnalyzedAlerts = anomalyAnalyzed?.length || 0;

  // lọc theo thời gian
  const [fromTs, setFromTs] = useState("");
  const [toTs, setToTs] = useState("");

  // giữ file để export (server)
  const [lastFile, setLastFile] = useState(null);

  async function uploadHandler(e) {
    try {
      const file = (e.files && e.files[0]) || null;
      if (!file) {
        setStatus("Vui lòng chọn một file.");
        return;
      }
      setLastFile(file);

      setStatus("⏳ Đang tải & phân tích...");
      setPreview([]); setResultsUp([]); setSummaryUp({});
      setResultsRaw([]); setSummaryRaw({}); setEventsPM([]);
      setProviderOpenAI(null); setStats(null); setValidateReport(null);
      setAnomalyReport(null); setAnomalyAnalyzed(null); setAnomalySummary(null);

      const fd = new FormData();
      fd.append("file", file);
      if (fromTs) fd.append("from", new Date(fromTs).toISOString());
      if (toTs) fd.append("to", new Date(toTs).toISOString());

      const res = await fetch(`${API_BASE}/analyze`, { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data?.error || "API error");

      // cấu trúc 4 bước mới
      setAnomalyReport(data.step2_summary || null);      // raw anomalies
      setAnomalyAnalyzed(data.step3_results || null);    // AI-analyzed
      setAnomalySummary(data.step4_summary || null);     // summary

      // fallback: cấu trúc cũ
      setPreview(data.preview || []);
      setResultsUp(data.results || []);
      setSummaryUp(data.summary || {});
      setResultsRaw(data.results_raw || []);
      setSummaryRaw(data.summary_raw || {});
      setEventsPM(data.events_per_minute || []);
      setProviderOpenAI(typeof data.used_openai === "boolean" ? data.used_openai : null);
      setStats(data.stats || null);
      setValidateReport(data.validate_report || null);

      // tự chuyển sang tab anomalies nếu có dữ liệu
      if (data.step3_results?.length) {
        setViewMode("anomalies");
      } else {
        setViewMode("upgraded");
      }
      setStatus("✅ Hoàn tất");
    } catch (err) {
      console.error(err);
      setStatus("❌ Lỗi: " + (err?.message || "Không xác định"));
    }
  }

  // export CSV (client)
  function exportCSVClient() {
    const rows = activeResults;
    const headers = ["log_index", "level", "summary", "suggestion", "collapsed_count", "upgrade_reason"];
    const esc = (v) => `"${String(v ?? "").replaceAll('"', '""')}"`;
    const csv = [
      headers.join(","),
      ...rows.map((r) =>
        [r.log_index, r.level, esc(r.summary), esc(r.suggestion), r.collapsed_count ?? 1, r.upgrade_reason ?? ""].join(",")
      ),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = viewMode === "upgraded" ? "log_analysis_upgraded.csv" : "log_analysis_raw.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  // export CSV (server)
  async function exportCSVServer() {
    try {
      if (!lastFile) {
        alert("Hãy phân tích (upload) ít nhất một lần trước khi export từ server.");
        return;
      }
      setStatus("⏳ Đang xuất CSV từ server...");
      const fd = new FormData();
      fd.append("file", lastFile);
      if (fromTs) fd.append("from", new Date(fromTs).toISOString());
      if (toTs) fd.append("to", new Date(toTs).toISOString());

      const res = await fetch(`${API_BASE}/export`, { method: "POST", body: fd });
      if (!res.ok) throw new Error("Export server thất bại");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "log_analysis_upgraded.csv";
      a.click();
      URL.revokeObjectURL(url);
      setStatus("✅ Đã tải CSV từ server");
    } catch (e) {
      console.error(e);
      setStatus("❌ Lỗi export server: " + (e?.message || "Không xác định"));
    }
  }

  // badge
  const Badge = ({ level, children }) => {
    const cls =
      level === "CRITICAL"
        ? "bg-red-100 text-red-800"
        : level === "WARNING"
          ? "bg-orange-100 text-orange-800"
          : "bg-sky-100 text-sky-800";
    return (
      <span className={`inline-block px-3 py-1 rounded-full text-xs font-semibold ${cls}`}>
        {children}
      </span>
    );
  };

  // kết quả theo chế độ xem + filter + search
  const activeResults = useMemo(() => {
    const base =
      viewMode === "upgraded"
        ? resultsUp
        : (resultsRaw || []).map((r, idx) => ({
          log_index: r.log_index ?? idx + 1,
          level: r.level,
          summary: r.summary,
          suggestion: r.suggestion,
          // raw chưa có count/reason
        }));

    const q = (query || "").toLowerCase().trim();
    return base.filter(
      (r) =>
        selectedLevels.has(String(r.level).toUpperCase()) &&
        (!q ||
          String(r.summary || "").toLowerCase().includes(q) ||
          String(r.suggestion || "").toLowerCase().includes(q))
    );
  }, [viewMode, resultsUp, resultsRaw, selectedLevels, query]);

  // thống kê theo chế độ xem
  const activeSummary = useMemo(
    () => (viewMode === "upgraded" ? summaryUp : summaryRaw) || {},
    [viewMode, summaryUp, summaryRaw]
  );

  function toggleLevel(lv) {
    setSelectedLevels((prev) => {
      const next = new Set(prev);
      if (next.has(lv)) next.delete(lv);
      else next.add(lv);
      return next;
    });
  }

  function resetFilters() {
    setSelectedLevels(new Set(["CRITICAL", "WARNING", "INFO"]));
    setQuery("");
    setAnomalyFilterLevel("");
    setAnomalyFilterType("");
  }

  const providerChip =
    providerOpenAI == null
      ? null
      : providerOpenAI
        ? <span className="px-2 py-1 rounded-lg bg-emerald-100 text-emerald-800 text-xs font-semibold">Provider: OpenAI</span>
        : <span className="px-2 py-1 rounded-lg bg-slate-100 text-slate-700 text-xs font-semibold">Provider: Heuristic</span>;

  const showingChip = (
    <span className="px-2 py-1 rounded-lg bg-indigo-50 text-indigo-700 text-xs font-semibold">
      {stats?.raw_rows
        ? `Showing ${stats.shown_rows} of ${stats.raw_rows} (−${stats.dedup_dropped})`
        : `Showing ${activeResults.length} rows`}
    </span>
  );

  const timeRangeChip =
    validateReport?.info?.time_range
      ? <span className="px-2 py-1 rounded-lg bg-sky-50 text-sky-700 text-xs font-semibold">
        Time: {validateReport.info.time_range[0]} → {validateReport.info.time_range[1]}
      </span>
      : null;

  // mapping lớp màu cố định cho risk level (tránh Tailwind purge)
  const riskLevelClass = (level) => {
    const map = {
      "Cực kỳ nguy cấp": "bg-red-100 text-red-700",
      "Cao": "bg-orange-100 text-orange-700",
      "Trung bình": "bg-yellow-100 text-yellow-700",
      "Thấp": "bg-emerald-100 text-emerald-700",
    };
    return map[level] || "bg-slate-100 text-slate-700";
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 p-6">
      <div className="max-w-6xl mx-auto bg-white rounded-2xl shadow-xl p-8 border border-slate-100">
        {/* Header Section */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 shadow-lg mb-4">
            <span className="text-3xl">🔍</span>
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
            Log Analyzer
          </h1>
          <p className="text-slate-500 mt-2 text-lg">
            Nền tảng phân tích log thông minh với AI
          </p>
        </div>

        {/* Feature Badges */}
        <div className="flex flex-wrap justify-center gap-2 mb-6">
          <span className="px-3 py-1.5 rounded-full bg-blue-50 text-blue-700 text-xs font-medium border border-blue-100">
            🔄 Chuẩn hóa tự động
          </span>
          <span className="px-3 py-1.5 rounded-full bg-emerald-50 text-emerald-700 text-xs font-medium border border-emerald-100">
            🧹 Lọc nhiễu thông minh
          </span>
          <span className="px-3 py-1.5 rounded-full bg-purple-50 text-purple-700 text-xs font-medium border border-purple-100">
            🤖 Phân tích AI
          </span>
          <span className="px-3 py-1.5 rounded-full bg-orange-50 text-orange-700 text-xs font-medium border border-orange-100">
            🚨 Phát hiện bất thường
          </span>
          <span className="px-3 py-1.5 rounded-full bg-rose-50 text-rose-700 text-xs font-medium border border-rose-100">
            📊 Đánh giá rủi ro
          </span>
        </div>

        {/* Supported Formats */}
        <div className="flex justify-center gap-1.5 mb-6">
          <span className="text-xs text-slate-400">Hỗ trợ:</span>
          {[".csv", ".json", ".ndjson", ".txt", ".log"].map((ext) => (
            <span key={ext} className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 text-xs font-mono">
              {ext}
            </span>
          ))}
        </div>

        {/* Upload */}
        <div className="flex justify-center">
          <div className="w-full max-w-xl">
            <FileUpload
              name="file"
              accept=".csv,.json,.ndjson,.txt,.log"
              customUpload
              uploadHandler={uploadHandler}
              mode="advanced"
              chooseLabel="Chọn file"
              uploadLabel="🚀 Phân tích"
              cancelLabel="Hủy"
              emptyTemplate={
                <div className="flex flex-col items-center justify-center text-gray-500 py-10 border-2 border-dashed border-slate-200 rounded-xl hover:border-blue-300 transition-colors">
                  <div className="w-14 h-14 rounded-full bg-blue-50 flex items-center justify-center mb-4">
                    <i className="pi pi-cloud-upload text-2xl text-blue-500"></i>
                  </div>
                  <p className="text-slate-600 font-medium">
                    Kéo & thả file vào đây
                  </p>
                  <p className="text-slate-400 text-sm mt-1">
                    hoặc bấm <span className="text-blue-600 font-semibold">Chọn file</span> để tải lên
                  </p>
                </div>
              }
            />
            <div className="text-slate-500 mt-2">{status}</div>
          </div>
        </div>

        {/* Controls */}
        <div className="mt-6 flex flex-wrap items-center gap-3">
          <div className="inline-flex rounded-lg overflow-hidden border border-slate-200">
            <button
              onClick={() => setViewMode("upgraded")}
              className={`px-3 py-2 text-sm ${viewMode === "upgraded" ? "bg-sky-600 text-white" : "bg-white text-slate-700"}`}
              title="Hiển thị sau hậu xử lý (nâng cấp mức độ)"
            >
              Sau hậu xử lý
            </button>
            <button
              onClick={() => setViewMode("raw")}
              className={`px-3 py-2 text-sm ${viewMode === "raw" ? "bg-sky-600 text-white" : "bg-white text-slate-700"}`}
              title="Kết quả phân tích AI gốc"
            >
              AI gốc
            </button>
            <button
              onClick={() => setViewMode("anomalies")}
              className={`px-3 py-2 text-sm ${viewMode === "anomalies" ? "bg-purple-600 text-white" : "bg-white text-slate-700"}`}
              title="Phát hiện bất thường + AI phân tích"
            >
              🔍 Anomalies (4-step)
            </button>
          </div>

          <div className="flex items-center gap-2 ml-2">
            {["CRITICAL", "WARNING", "INFO"].map((lv) => (
              <label key={lv} className="flex items-center gap-1 text-sm text-slate-700">
                <input type="checkbox" checked={selectedLevels.has(lv)} onChange={() => toggleLevel(lv)} />
                <span>{lv}</span>
                {activeSummary?.[lv] != null && <span className="text-slate-400">({activeSummary[lv]})</span>}
              </label>
            ))}
          </div>

          {/* Anomaly-specific filters */}
          {viewMode === "anomalies" && anomalySubjects.length > 0 && (
            <div className="flex items-center gap-2 ml-2">
              <select
                value={anomalyFilterType}
                onChange={(e) => setAnomalyFilterType(e.target.value)}
                className="px-2 py-1 border rounded text-sm bg-white"
              >
                <option value="">All Types</option>
                {anomalySubjectTypes.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
              <select
                value={anomalyFilterLevel}
                onChange={(e) => setAnomalyFilterLevel(e.target.value)}
                className="px-2 py-1 border rounded text-sm bg-white"
              >
                <option value="">All Risk Levels</option>
                <option value="Thấp">Thấp (Low)</option>
                <option value="Trung bình">Trung bình (Medium)</option>
                <option value="Cao">Cao (High)</option>
                <option value="Cực kỳ nguy cấp">Cực kỳ nguy cấp (Critical)</option>
              </select>
            </div>
          )}

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Tìm theo tóm tắt / gợi ý…"
            className="flex-1 min-w-[220px] px-3 py-2 border rounded-lg text-sm outline-none focus:ring-2 ring-sky-300"
          />

          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-700">Từ</label>
            <input type="datetime-local" value={fromTs} onChange={(e) => setFromTs(e.target.value)} className="px-2 py-1 border rounded" />
            <label className="text-sm text-slate-700">Đến</label>
            <input type="datetime-local" value={toTs} onChange={(e) => setToTs(e.target.value)} className="px-2 py-1 border rounded" />
          </div>

          <button onClick={resetFilters} className="px-3 py-2 text-sm rounded-lg border bg-white hover:bg-slate-50">
            Xoá lọc
          </button>

          <button onClick={exportCSVClient} className="px-3 py-2 text-sm rounded-lg bg-emerald-600 text-white hover:bg-emerald-700">
            ⬇️ Export CSV (client)
          </button>
          <button onClick={exportCSVServer} className="px-3 py-2 text-sm rounded-lg bg-indigo-600 text-white hover:bg-indigo-700">
            ⬇️ Export CSV (server)
          </button>
        </div>

        {/* Banner chips */}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {providerChip}
          {showingChip}
          {timeRangeChip}
          {stats?.alerts != null && (
            <span className="px-2 py-1 rounded-lg bg-purple-50 text-purple-700 text-xs font-semibold">
              Alerts (analyze): {stats.alerts}
            </span>
          )}
        </div>

        {/* Data quality */}
        {validateReport && (
          <div className="mt-4 border rounded-lg p-3 bg-slate-50">
            <div className="flex items-center justify-between">
              <div className="font-semibold text-slate-700">🩺 Data quality</div>
              <div className={`text-xs px-2 py-0.5 rounded ${validateReport.ok ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700"}`}>
                {validateReport.ok ? "OK" : "Needs attention"}
              </div>
            </div>
            {!validateReport.ok && (
              <ul className="list-disc ml-5 mt-2 text-sm text-amber-700">
                {(validateReport.issues || []).map((it, idx) => <li key={idx}>{it}</li>)}
              </ul>
            )}
            <div className="mt-2 text-xs text-slate-600">
              Rows: {validateReport.info?.rows ?? "?"} · Columns: {Array.isArray(validateReport.info?.columns) ? validateReport.info.columns.length : "?"}
            </div>
          </div>
        )}

        {/* Bảng kết quả + Anomaly Results */}
        <h2 className="text-xl font-semibold text-slate-800 mt-6">📑 Kết quả phân tích</h2>

        {/* ANOMALY DETECTION RESULTS (4-STEP) */}
        {viewMode === "anomalies" ? (
          (anomalyReport || anomalyAnalyzed) ? (
            <div className="mt-4 space-y-4">
              {/* Step 2: Raw Anomalies Summary */}
              {anomalyReport && (
                <div className="border rounded-lg p-4 bg-purple-50">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-purple-900">📊 Phát hiện Bất thường (Raw Anomalies)</h3>
                    <span className="px-3 py-1 rounded-lg bg-purple-100 text-purple-700 text-sm font-semibold">
                      {anomalyReport.total_alerts} alerts
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                    <div className="bg-white p-3 rounded border-l-4 border-red-500">
                      <div className="text-xs text-slate-600">CRITICAL</div>
                      <div className="text-2xl font-bold text-red-600">{anomalyReport.severity_breakdown?.CRITICAL || 0}</div>
                    </div>
                    <div className="bg-white p-3 rounded border-l-4 border-orange-500">
                      <div className="text-xs text-slate-600">WARNING</div>
                      <div className="text-2xl font-bold text-orange-600">{anomalyReport.severity_breakdown?.WARNING || 0}</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Step 4: AI-Analyzed (grouped by subject) */}
              {anomalySubjects.length > 0 && (
                <div className="border rounded-lg p-4 bg-indigo-50">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-indigo-900">🤖 Phân tích từ AI</h3>
                    <span className="px-3 py-1 rounded-lg bg-indigo-100 text-indigo-700 text-sm font-semibold flex flex-col leading-tight">
                      <span>{totalAnalyzedSubjects} subjects</span>
                      {totalAnalyzedAlerts > 0 && (
                        <span className="text-xs text-slate-600">{totalAnalyzedAlerts} alerts</span>
                      )}
                    </span>
                  </div>

                  {/* Tóm tắt phân bố mức rủi ro */}
                  {anomalySummary && (
                    <div className="mb-3 p-3 bg-white rounded border-l-4 border-indigo-500">
                      <div className="text-xs text-slate-600 mb-1">Risk Level Breakdown</div>
                      <div className="flex gap-2 flex-wrap">
                        {Object.entries(anomalySummary.by_risk_level || {}).map(([level, count]) => (
                          <span key={level} className="px-2 py-1 bg-indigo-100 text-indigo-700 rounded text-sm">
                            {level}: {count}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Cards theo subject */}
                  <div className="space-y-2">
                    {(() => {
                      const subjects = filteredAnomalySubjects;
                      if (!subjects.length) {
                        return <div className="text-slate-500 text-sm">Không có kết quả.</div>;
                      }

                      return subjects.map((subject, idx) => {
                        const severityClass =
                          subject.severity === "CRITICAL" ? "text-red-600" :
                            subject.severity === "WARNING" ? "text-orange-600" :
                              subject.severity === "INFO" ? "text-yellow-600" :
                                "text-slate-600";

                        const alertTypesLabel = subject.alertTypes.length
                          ? subject.alertTypes.join(", ")
                          : "unknown";

                        const sampleAlerts = subject.alerts.slice(0, 2);

                        return (
                          <div key={`${subject.subject}-${idx}`} className="bg-white p-3 rounded border-l-4 border-indigo-400">
                            <div className="flex items-start justify-between mb-2">
                              <div>
                                <div className="font-semibold text-slate-800 flex items-center gap-2">
                                  {(subject.subject || "").toLowerCase() === "unknown" ? (
                                    <>
                                      <span className="text-2xl">🚨</span>
                                      <span className="text-red-700">{subject.subject}</span>
                                      <span className="px-2 py-0.5 bg-red-100 text-red-700 text-xs font-bold  rounded uppercase border border-red-300">
                                        ⚠️ ROGUE DEVICE
                                      </span>
                                    </>
                                  ) : (
                                    subject.subject
                                  )}
                                </div>
                                <div className="text-xs text-slate-600">
                                  {alertTypesLabel} | {subject.alert_count} alerts
                                </div>
                              </div>
                              <div className={`px-2 py-1 rounded text-sm font-semibold ${riskLevelClass(subject.ai_analysis?.risk_level)}`}>
                                {subject.ai_analysis?.risk_level || "Unknown"}
                              </div>
                            </div>

                            <div className="bg-slate-50 p-3 rounded border-l-4 border-indigo-300 mb-3">
                              <div className="text-xs text-slate-600 font-semibold mb-1">Sự kiện</div>
                              <div className="text-sm text-slate-800 space-y-1">
                                {sampleAlerts.length ? (
                                  sampleAlerts.map((item, sampleIdx) => (
                                    <div key={sampleIdx}>- {item.text || "Không có mô tả"}</div>
                                  ))
                                ) : (
                                  <div>Không có mô tả</div>
                                )}
                                {subject.alert_count > sampleAlerts.length && (
                                  <div className="text-xs text-slate-500">
                                    +{subject.alert_count - sampleAlerts.length} alert khác...
                                  </div>
                                )}
                              </div>
                            </div>

                            <div className="text-sm mb-2">
                              <strong>Tóm tắt phân tích:</strong>
                              <div className="text-slate-700 mt-1">{subject.ai_analysis?.summary}</div>
                            </div>

                            {subject.ai_analysis?.risks && subject.ai_analysis.risks.length > 0 && (
                              <div className="text-sm mb-2">
                                <strong>Rủi ro:</strong>
                                <ul className="list-disc ml-5 text-slate-700 mt-1">
                                  {subject.ai_analysis.risks.map((risk, i) => (
                                    <li key={i}>{risk}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {subject.ai_analysis?.actions && subject.ai_analysis.actions.length > 0 && (
                              <div className="text-sm">
                                <strong>Hành động đề xuất:</strong>
                                <ul className="list-disc ml-5 text-slate-700 mt-1">
                                  {subject.ai_analysis.actions.map((action, i) => (
                                    <li key={i}>{action}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            <div className="mt-3 pt-3 border-t border-slate-200 flex gap-4 justify-between">
                              <div className="flex-1">
                                <div className="text-xs text-slate-600 font-semibold">Score</div>
                                <div className="text-lg font-bold text-indigo-600">
                                  {typeof subject.score === "number" ? subject.score.toFixed(2) : "N/A"}
                                </div>
                              </div>
                              <div className="flex-1">
                                <div className="text-xs text-slate-600 font-semibold">Severity</div>
                                <div className={`text-lg font-bold ${severityClass}`}>
                                  {subject.severity || "N/A"}
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      });
                    })()}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="mt-4 p-4 bg-slate-50 rounded-lg border border-slate-200">
              <p className="text-slate-500 text-sm">Chưa có dữ liệu.</p>
            </div>
          )
        ) : (
          <div className="overflow-x-auto mt-2">
            <table className="min-w-full border-collapse">
              <thead>
                <tr className="bg-slate-50 text-slate-600">
                  <th className="text-left py-2 px-3">#</th>
                  <th className="text-left py-2 px-3">Count</th>
                  <th className="text-left py-2 px-3">Level</th>
                  <th className="text-left py-2 px-3">Tóm tắt</th>
                  <th className="text-left py-2 px-3">Gợi ý</th>
                  <th className="text-left py-2 px-3">Reason</th>
                </tr>
              </thead>
              <tbody>
                {activeResults.length ? (
                  activeResults.map((r, idx) => (
                    <tr key={`${r.log_index}-${idx}`} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="py-2 px-3">{r.log_index ?? idx + 1}</td>
                      <td className="py-2 px-3">{r.collapsed_count ?? 1}</td>
                      <td className="py-2 px-3"><Badge level={r.level}>{r.level}</Badge></td>
                      <td className="py-2 px-3">{r.summary}</td>
                      <td className="py-2 px-3">{r.suggestion}</td>
                      <td className="py-2 px-3">{r.upgrade_reason || ""}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td className="py-3 px-3 text-slate-500" colSpan={6}>
                      Chưa có dữ liệu.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
