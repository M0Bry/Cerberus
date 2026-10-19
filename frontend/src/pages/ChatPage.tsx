/**
 * Chat Page (app home) — ported from the new front-end's home.html + js/chat.js,
 * rewired from mock replies to the real AI conversation endpoints:
 *
 *   POST /ai/:engagementId/message  {message, context?}
 *   GET  /ai/:engagementId/history
 *
 * Engagement resolution:
 *   /chat/:id  → the engagement from the URL
 *   /chat      → the user's most recent engagement
 *   (none)     → the first message lazily creates an engagement, then sends.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { chatApi, type ChatMessageItem } from "../api/chatApi";
import { engagementApi } from "../api/engagementApi";
import { rulesApi } from "../api/rulesApi";
import { useAccess } from "../hooks/useAccess";
import { useAuthStore } from "../store/useAuthStore";
import type { Engagement } from "../types";
import { checkChatMessage, checkSignatureName, LIMITS } from "../utils/validators";

export default function ChatPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const user = useAuthStore((s) => s.user);
  const { data: access } = useAccess(!!user);
  const isSuspended = access?.state === "suspended";

  /* ── engagement resolution ─────────────────────────────────────── */
  const listQuery = useQuery({
    queryKey: ["engagements", "list"],
    queryFn: async () => (await engagementApi.list({ page: 1, page_size: 100 })).data,
    enabled: !id,
  });
  const byIdQuery = useQuery({
    queryKey: ["engagements", id],
    queryFn: async () => (await engagementApi.get(id!)).data,
    enabled: !!id,
  });

  const active: Engagement | undefined =
    (byIdQuery.data as Engagement | undefined) ??
    (listQuery.data?.items?.[0] as Engagement | undefined);

  /* ── messages ──────────────────────────────────────────────────── */
  const historyQuery = useQuery({
    queryKey: ["chat", "history", active?.id],
    queryFn: async () => (await chatApi.getHistory(active!.id)).data,
    enabled: !!active,
  });

  type Msg = ChatMessageItem & { follow_ups?: string[] };
  const [local, setLocal] = useState<Msg[]>([]);
  const [text, setText] = useState("");
  const [setupNote, setSetupNote] = useState("");
  const logRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    setLocal([]);
  }, [active?.id]);

  /* seed local messages from the loaded history (history messages have no follow-ups).
     Skipped when the user already sent a message before the history resolved. */
  useEffect(() => {
    if (historyQuery.data?.messages && local.length === 0) setLocal(historyQuery.data.messages);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [historyQuery.data]);

  const messages = local;

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [messages.length]);

  /* ── Scope of Engagement + Rules of Engagement (document stage) ──
     The backend creates the document automatically once the conversation
     has gathered enough information. The document is part of the SAME
     page — it appears in place of the chat, the client reviews it and
     signs by typing their full legal name (paste disabled). If the
     client re-opens the engagement unsigned, the document shows again. */
  const [docOpen, setDocOpen] = useState(false);
  const [signName, setSignName] = useState("");
  const [signError, setSignError] = useState("");

  const rulesQuery = useQuery({
    queryKey: ["rules", active?.id],
    queryFn: async () => (await rulesApi.get(active!.id)).data,
    enabled: !!active,
    retry: false,
    staleTime: 0,
  });
  const doc = rulesQuery.data; // undefined while loading or when 404 (no doc yet)

  useEffect(() => {
    if (doc && !doc.is_signed) setDocOpen(true);
    if (doc?.is_signed) setDocOpen(false);
  }, [doc?.id, doc?.is_signed]); // eslint-disable-line react-hooks/exhaustive-deps

  const signMutation = useMutation({
    mutationFn: async (signedName: string) =>
      (await rulesApi.sign(active!.id, { signed_name: signedName })).data,
    onSuccess: () => {
      setSignError("");
      setDocOpen(false);
      queryClient.invalidateQueries({ queryKey: ["rules", active?.id] });
      queryClient.invalidateQueries({ queryKey: ["engagements"] });
    },
    onError: (err: any) => {
      setSignError(
        err?.response?.data?.error?.message ||
          err?.response?.data?.detail ||
          "Signature failed. Please try again."
      );
    },
  });

  /* ── send ──────────────────────────────────────────────────────── */
  const [sending, setSending] = useState(false);

  const doSend = useCallback(
    async (message: string) => {
      if (!message || sending) return;
      const msgErr = checkChatMessage(message);
      if (msgErr) return;
      // Access gate (mirrors the backend 403): suspended accounts cannot
      // start new assessments until a subscription is active.
      if (isSuspended) {
        setSetupNote(
          "Your free trial has ended and the account is suspended — choose a plan on the Billing page to continue."
        );
        return;
      }
      setSending(true);
      setSetupNote("");
      try {
        let eng = active;
        if (!eng) {
          setSetupNote("Setting up your assessment…");
          const created = (
            await engagementApi.create({
              project_name: message.length > 60 ? message.slice(0, 60) + "…" : message,
              organization_name: user?.company_name || "My Organization",
              objective: message,
            })
          ).data;
          eng = created;
          queryClient.invalidateQueries({ queryKey: ["engagements"] });
        }
        const res = (await chatApi.sendMessage(eng.id, { message })).data;
        setLocal((p) => [
          ...p,
          { role: "user", content: message },
          { role: "assistant", content: res.ai_response, follow_ups: res.follow_up_questions },
        ]);
        queryClient.invalidateQueries({ queryKey: ["engagements"] });

        // Conversation complete → the official document is ready.
        // (Never re-open it if it was already signed.)
        if (res.next_stage === "document" && !doc?.is_signed) {
          await queryClient.invalidateQueries({ queryKey: ["rules", eng.id] });
          setDocOpen(true);
        }
      } catch (err: any) {
        setLocal((p) => [
          ...p,
          { role: "user", content: message },
          {
            role: "assistant",
            content:
              err?.response?.data?.error?.message ||
              err?.response?.data?.detail ||
              "The agent did not respond. Please check your connection and try again.",
          },
        ]);
      } finally {
        setSending(false);
        setSetupNote("");
      }
    },
    [active, queryClient, sending, user, doc, isSuspended]
  );

  const submit = (e?: React.FormEvent) => {
    e?.preventDefault();
    const value = text.trim();
    if (!value) return;
    setText("");
    if (inputRef.current) inputRef.current.style.height = "auto";
    void doSend(value);
  };

  const onKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  const onInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setText(e.target.value);
    const el = e.currentTarget;
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 160) + "px";
  };

  const hasMsgs = messages.length > 0 || sending;

  /* ── Document stage: the page itself becomes the document ───────── */
  if (docOpen && doc) {
    return (
      <main className="chat-main">
        <section className="doc-stage">
          <header className="doc-bar">
            <div className="doc-bar-title">
              <i className="fas fa-file-signature" />
              <span>Scope of Engagement &amp; Rules of Engagement</span>
            </div>
            <span className="doc-bar-meta">
              {active?.engagement_number || (active?.id ? active.id.slice(0, 8).toUpperCase() : "—")}
              {" · PENDING SIGNATURE"}
            </span>
          </header>

          <div className="doc-scroll">
            <article
              className="roe-card"
              dangerouslySetInnerHTML={{ __html: doc.document_html }}
            />
          </div>

          <footer className="doc-sign">
            <label htmlFor="signName">
              Sign to authorize — type your full legal name <b>exactly as registered</b>.
              Copy-paste is disabled; the signature must be entered deliberately.
            </label>
            <div className="doc-sign-row">
              <input
                id="signName"
                type="text"
                maxLength={LIMITS.signatureName.max}
                value={signName}
                disabled={signMutation.isPending}
                onChange={(e) => {
                  setSignName(e.target.value);
                  if (signError) setSignError("");
                }}
                onPaste={(e) => e.preventDefault()}
                onDrop={(e) => e.preventDefault()}
                placeholder="Type your full legal name"
                autoComplete="off"
                spellCheck={false}
              />
              <button
                type="button"
                className="btn btn-primary doc-sign-btn"
                disabled={signMutation.isPending || signName.trim().length < 3}
                onClick={() => {
                  const sErr = checkSignatureName(signName);
                  if (sErr) return setSignError(sErr);
                  void signMutation.mutate(signName.trim());
                }}
              >
                {signMutation.isPending ? (
                  <>
                    <i className="fas fa-spinner fa-spin" /> Sealing…
                  </>
                ) : (
                  <>
                    <i className="fas fa-file-signature" /> Accept and Sign
                  </>
                )}
              </button>
            </div>
            {signError && (
              <div className="alert show err" style={{ marginTop: 10 }}>
                {signError}
              </div>
            )}
          </footer>
        </section>
      </main>
    );
  }

  return (
    <main className="chat-main">
      <section className={`chat-stage${hasMsgs ? " has-msgs" : ""}`} id="chatStage">
        {!hasMsgs && <h1 className="chat-hero">What should we explore?</h1>}

        {isSuspended && (
          <div className="access-banner suspended">
            <div className="access-banner-ico">
              <i className="fas fa-lock" />
            </div>
            <div className="access-banner-body">
              <b>Free trial ended — account suspended</b>
              <span>
                Your 7-day free trial has ended. Choose a plan to restore access and
                start new assessments.
              </span>
              <Link className="btn btn-primary" to="/billing">
                <i className="fas fa-credit-card" /> Choose a plan
              </Link>
            </div>
          </div>
        )}

        <div className="chat-log" id="chatLog" ref={logRef}>
          {doc?.is_signed && (
            <div className="msg ai doc-chip">
              <span className="who">Cerberus Agent</span>
              <span>
                <i className="fas fa-file-signature" />{" "}
                <b>Engagement authorized &amp; active.</b> The signed Scope of Engagement
                &amp; Rules of Engagement is on file
                {doc.signed_at ? ` — signed ${new Date(doc.signed_at).toLocaleString()}` : ""}.
              </span>
            </div>
          )}
          {messages.map((m, i) => (
            <div className={`msg ${m.role === "user" ? "user" : "ai"}`} key={i}>
              {m.role === "assistant" && <span className="who">Cerberus Agent</span>}
              {m.content}
              {m.role === "assistant" && m.follow_ups && m.follow_ups.length > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 }}>
                  {m.follow_ups.map((q, j) => (
                    <button key={j} type="button" className="chip" onClick={() => void doSend(q)}>
                      {q}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
          {setupNote && (
            <div className="msg ai">
              <span className="who">Cerberus Agent</span>
              {setupNote}
            </div>
          )}
          {sending && !setupNote && (
            <div className="msg ai">
              <span className="who">Cerberus Agent</span>
              Thinking…
            </div>
          )}
        </div>

        {isSuspended ? (
          <div className="chat-box access-locked" aria-disabled="true">
            <span>
              <i className="fas fa-lock" /> New assessments are locked while your
              account is suspended
            </span>
          </div>
        ) : (
          <form className="chat-box" id="chatForm" noValidate autoComplete="off" onSubmit={submit}>
            <textarea
              id="chatInput"
              ref={inputRef}
              rows={1}
              maxLength={LIMITS.chatMessage.max}
              placeholder="Type your message"
              aria-label="Message Cerberus Agent"
              value={text}
              onChange={onInput}
              onKeyDown={onKey}
            />
          </form>
        )}
      </section>
    </main>
  );
}
