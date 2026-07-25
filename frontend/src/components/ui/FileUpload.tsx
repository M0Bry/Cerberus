/**
 * FileUpload — Drag & drop file upload matching the reference design.
 */
import { useState, useRef, DragEvent, ChangeEvent } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  accept?: string;
  maxSizeMB?: number;
  label?: string;
  hint?: string;
  error?: string;
}

export default function FileUpload({
  onFileSelect, accept = ".pdf,.docx,.xlsx,.txt,.csv,.json,.zip",
  maxSizeMB = 50, label, hint, error,
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = (file: File) => {
    if (file.size > maxSizeMB * 1024 * 1024) {
      alert(`File exceeds ${maxSizeMB}MB limit`);
      return;
    }
    setFileName(file.name);
    onFileSelect(file);
  };

  return (
    <div style={{ marginBottom: 16 }}>
      {label && (
        <label style={{ display: "block", fontSize: 12.5, color: "#8493ac", marginBottom: 7, fontFamily: MONO }}>
          {label}
        </label>
      )}
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={(e: DragEvent) => { e.preventDefault(); setIsDragging(false); if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]); }}
        onClick={() => inputRef.current?.click()}
        style={{
          border: `1px dashed ${isDragging ? "#2f7dfa" : error ? "#f4536b" : "#152238"}`,
          borderRadius: 12,
          padding: "28px 20px",
          textAlign: "center",
          cursor: "pointer",
          background: isDragging ? "rgba(47,125,250,0.06)" : "rgba(4,8,16,0.5)",
          transition: "all 0.2s",
          fontFamily: MONO,
        }}
      >
        <input ref={inputRef} type="file" accept={accept} onChange={(e: ChangeEvent<HTMLInputElement>) => { if (e.target.files?.length) handleFile(e.target.files[0]); }} style={{ display: "none" }} />
        {fileName ? (
          <div>
            <span style={{ fontSize: 24 }}>📎</span>
            <p style={{ fontSize: 13, color: "#e8edf7", marginTop: 8 }}>{fileName}</p>
            <p style={{ fontSize: 11, color: "#5b6a86", marginTop: 4 }}>Click to replace</p>
          </div>
        ) : (
          <div>
            <span style={{ fontSize: 28 }}>📁</span>
            <p style={{ fontSize: 13, color: "#8493ac", marginTop: 8 }}>Drag & drop files here, or click to select</p>
            <p style={{ fontSize: 11, color: "#5b6a86", marginTop: 4 }}>Supported: {accept} (max {maxSizeMB}MB)</p>
          </div>
        )}
      </div>
      {hint && !error && <p style={{ marginTop: 4, fontSize: 11, color: "#5b6a86", fontFamily: MONO }}>{hint}</p>}
      {error && <p style={{ marginTop: 4, fontSize: 11, color: "#f4536b", fontFamily: MONO }}>{error}</p>}
    </div>
  );
}
