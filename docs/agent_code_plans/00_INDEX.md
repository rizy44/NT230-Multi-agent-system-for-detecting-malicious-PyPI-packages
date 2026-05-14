# LAMPS MCP Agent Code Plans

Thư mục này là bộ kế hoạch điều hướng cho agent/code worker triển khai MCP server hỗ trợ dự án LAMPS replica.

Đọc theo thứ tự:

1. `01_MCP_SERVER_OVERVIEW.md` - kiến trúc, mục tiêu, phạm vi.
2. `02_TOOL_CONTRACTS.md` - danh sách MCP tools, input/output schema.
3. `03_IMPLEMENTATION_TASKS.md` - task-by-task plan để code.
4. `04_TEST_AND_VERIFICATION.md` - test plan và lệnh kiểm chứng.
5. `05_AGENT_HANDOFF.md` - chỉ dẫn ngắn cho agent nhận việc.

Nguyên tắc quan trọng:

- Dùng lệnh `python`, không dùng `py`.
- Không execute package PyPI, không import code từ archive tải về.
- API key LLM là optional. Tool scan vẫn phải chạy được với `classifier="heuristic"`.
- MCP server chỉ gọi lại các module có sẵn trong `lamps/`, không copy logic sang nhánh code riêng.
- CodeBERT checkpoint mặc định nằm ở `CodeBERT_Classifier/checkpoint` nếu train thành công.
