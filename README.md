# Post-Investment Report Analyst Agent (Python)

A personal project that turns messy **PDF post-investment reports / quarterly updates / financial statements** into a searchable knowledge base and an **agent** that can answer questions **with citations** and **reliable calculations** (QoQ/YoY growth, comparisons).

This is **not** a generic “chatbot”. The goal is a **real, evaluatable, end-to-end agent system**:
PDF parsing → RAG retrieval → tool calling for math → cited answers → evaluation & iteration.

---

## ✨ Features

- **PDF ingestion & parsing**
  - Extract text + page numbers (foundation for citations)
  - Optional: table extraction and OCR for scanned PDFs
- **RAG Q&A**
  - Chunk reports, embed chunks, store in a local vector index (FAISS)
  - Retrieve top-k relevant context and generate answers grounded in evidence
- **Citations / traceability**
  - Answers include citations: `doc_id / page / chunk`
- **Tool Use (Function Calling)**
  - Detect computation intent (growth rate, delta, ratio)
  - Extract numbers from evidence and call deterministic Python functions
- **Evaluation pipeline**
  - Run a benchmark set (questions + gold answers + evidence hints)
  - Track correctness, evidence hit rate, latency, and cost

---

## 🧠 Example Questions

- “What is Company A’s revenue QoQ growth this quarter?”
- “What are Company B’s key risks this quarter? Cite the report sections.”
- “Compare user growth between Company C and D and explain the gap (with citations).”

---

## 🏗️ High-Level Architecture

1. **Parsing layer**: PDF → structured JSON (text/table/OCR + page numbers)
2. **Indexing layer**: chunk → embedding → vector index (FAISS)
3. **Retrieval layer**: question → (optional multi-query / HyDE) → top-k chunks
4. **Reasoning layer**: LLM answers using retrieved context + citation rules
5. **Tools layer**: math/comparisons done by deterministic Python functions
6. **Evaluation layer**: benchmark run + error categorization + ablations

---

## 📁 Repository Layout

```text
post-investment-analyst/
  README.md
  requirements.txt
  .env.example

  data/
    pdfs/                 # put raw PDFs here (doc_id.pdf)

