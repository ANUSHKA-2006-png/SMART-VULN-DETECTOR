import { useState } from "react";
import axios from "axios";
import { ShieldCheck, ShieldAlert, Activity, Code2 } from "lucide-react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { atomOneDark } from "react-syntax-highlighter/dist/esm/styles/hljs";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

const API = "http://127.0.0.1:8000/api";

export default function App() {
  const [code, setCode] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  async function analyze() {
    setLoading(true);
    const res = await axios.post(`${API}/analyze`, {
      source_code: code,
      use_ml: true
    });
    setResult(res.data);
    setLoading(false);
  }

  const COLORS = ["#ef4444", "#f59e0b", "#22c55e"];

  
  const chartData = result ? [
  { name: "High", value: result.summary.high },
  { name: "Medium", value: result.summary.medium },
  { name: "Low", value: result.summary.low }
] : [];

  const riskColor = {
    Safe: "#16a34a",
    Medium: "#f59e0b",
    High: "#dc2626",
    Critical: "#7f1d1d"
  };
  // 🔥 AI label + color
  const aiLabel =
    result?.ml_prediction?.predicted_class === "0"
      ? "Safe"
      : "Vulnerable";

  const aiColor =
    aiLabel === "Safe" ? "#22c55e" : "#ef4444";
  return (
    <div style={{
      minHeight: "100vh",
      background: "linear-gradient(135deg,#020617,#0f172a,#1e293b)",
      color: "white",
      fontFamily: "Arial",
      padding: 20
    }}>

      {/* HEADER */}
      <div style={{ textAlign: "center", marginBottom: 30 }}>
        <h1>🚀 Smart Contract Vulnerability Detector</h1>
        <p style={{ color: "#94a3b8" }}>
          AI + Static Analysis for Blockchain Security
        </p>
      </div>

      {/* INPUT */}
      <textarea
        rows={12}
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder="Paste Solidity code..."
        style={{
          width: "100%",
          padding: 15,
          borderRadius: 12,
          background: "rgba(255,255,255,0.05)",
          backdropFilter: "blur(10px)",
          color: "white",
          border: "1px solid #334155"
        }}
      />

      <br /><br />

      {/* BUTTON */}
      <button
        onClick={analyze}
        style={{
          padding: "12px 25px",
          background: "#3b82f6",
          border: "none",
          borderRadius: 8,
          cursor: "pointer"
        }}
      >
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      <br /><br />

      {result && (
        <>
          {/* RISK CARD */}
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 15,
            padding: 20,
            borderRadius: 12,
            background: riskColor[result.risk_level]
          }}>
            {result.risk_level === "Safe"
              ? <ShieldCheck size={30} />
              : <ShieldAlert size={30} />
            }

            <div>
              <h2>
                🛡 Static Analysis: {result.risk_level}
              </h2>
              <p>Score: {result.risk_score}</p>
            </div>
          </div>

          <br />

          {/* PIE CHART */}
          <div style={{
            background: "rgba(255,255,255,0.05)",
            padding: 20,
            borderRadius: 12,
            marginBottom: 20
          }}>
            <h3>📊 Risk Distribution</h3>

            <PieChart width={300} height={250}>
              <Pie data={chartData} dataKey="value" outerRadius={80}>
                {chartData.map((entry, index) => (
                  <Cell key={index} fill={COLORS[index]} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </div>

          {/* ML */}
          <div style={{
            background: "rgba(255,255,255,0.05)",
            padding: 15,
            borderRadius: 12,
            marginBottom: 20
          }}>
            <h3><Activity size={18}/> AI Prediction</h3>

            {result.ml_prediction?.error ? (
              <p>Error: {result.ml_prediction.error}</p>
            ) : (
              <>
                <p style={{ color: aiColor }}>
                  Prediction: <b>{aiLabel}</b>
                </p>
                <p>
                  Confidence: {(result.ml_prediction.confidence * 100).toFixed(2)}%
                </p>
              </>
            )}
          </div>

          {/* FIXES */}
          <div style={{
            background: "rgba(255,255,255,0.05)",
            padding: 15,
            borderRadius: 12,
            marginBottom: 20
          }}>
            <h3>🛠 Fix Suggestions</h3>

            {result.findings.length === 0
              ? <p>No major issues found</p>
              : result.findings.map((f, i) => (
                <div key={i}>
                  <b>{f.name}</b>
                  <p>{f.description}</p>
                </div>
              ))}
          </div>

          {/* CODE VIEW */}
          <div style={{
            background: "#020617",
            padding: 15,
            borderRadius: 12
          }}>
            <h3><Code2 size={18}/> Code View</h3>

            <SyntaxHighlighter language="solidity" style={atomOneDark}>
              {code}
            </SyntaxHighlighter>
          </div>
        </>
      )}
    </div>
  );
}