import json
import time
import re
from tools import PentestToolbox
from config import get_ollama_client, OLLAMA_MODEL, TARGET_IP
from task_tree import TaskTree  
import logging
from dataclasses import dataclass, field
from prompt import get_stage1_system_prompt, get_stage2_system_prompt, get_stage3_system_prompt
import util

ollama_client = get_ollama_client()
logger = logging.getLogger(__name__)

# =============================================================================
# 模組們
# =============================================================================

def ai_parsing_module(raw_log, prior_context=""):
    """【Stage 1: 感知模組】分析最新 Nmap/掃描日誌，回傳標準化 JSON"""
    print("\n[感知模組 Stage 1] 正在叫 Qwen2.5-Coder 分析最新日誌...")

    raw_log_str = str(raw_log)

    # 1. 修改條件：只要包含 /tcp 或 /udp 或是 Nmap 特徵字，就進行適度日誌清理
    if any(
        k in raw_log_str for k in ["PORT", "/tcp", "/udp", "Nmap scan report"]
    ):
        cleaned_lines = []
        for line in raw_log_str.split("\n"):
            line_str = line.strip()
            # 保留含有關鍵資訊的行（包含表頭、分隔線、TCP、UDP 與 Nmap 關鍵字）
            if any(
                k in line_str
                for k in [
                    "/tcp",
                    "/udp",
                    "PORT",
                    "STATE",
                    "SERVICE",
                    "Nmap scan report",
                    "===",
                ]
            ):
                cleaned_lines.append(line_str)

        if len(cleaned_lines) > 1:
            raw_log = "\n".join(cleaned_lines)
            print("\n==================================================")
            print("Nmap 日誌：")
            print("--------------------------------------------------")
            print(raw_log)
            print("==================================================")

    system_prompt = get_stage1_system_prompt()
    user_content = f"""{prior_context}

=== NEW EXECUTED RAW LOG TO ANALYZE ===
{raw_log}"""

    return _call_ollama_and_parse_json(system_prompt, user_content, "Stage 1")


def ai_parsing_stage2(raw_log: str, prior_context: str = "") -> dict:
    """
    【Stage 2: 推理模組】
    解析預先排序好的 CVE 報告，進行目標選擇與 RAG 檢索語句生成。
    """
    print("\n[🧠 推理模組 Stage 2] 正在分析 CVE 報告並鎖定利用目標 (PentestGPT Mode)...")
    
    # 1. 載入獨立管理之 System Prompt
    system_prompt = get_stage2_system_prompt()
    
    # 2. 組裝 User Content
    user_content = f"""{prior_context}

=== NVD SEARCHED CVE REPORT TO EVALUATE ===
{raw_log}"""

    # 3. 呼叫 LLM 進行推理並解析 JSON
    parsed_result = _call_ollama_and_parse_json(system_prompt, user_content, "Stage 2 Reasoning")
    
    # 4. 終端機日誌列印
    if parsed_result and parsed_result.get("status") == "success":
        stage2_info = parsed_result.get("stage2_status", {})
        target_cve = stage2_info.get("selected_target_cve", "None")
        reason = stage2_info.get("reason", "No reason provided.")
        rag_query = stage2_info.get("rag_search_query", "None")
        
        print(f"  └─ 🎯 [推理決策] 鎖定目標 CVE: \033[91m{target_cve}\033[0m")
        print(f"  └─ 💡 [決策邏輯]: {reason}")
        print(f"  └─ 🔍 [RAG 檢索指令]: {rag_query}")
    else:
        print("  └─ ⚠️ [推理失敗] 無法產出有效決策，請檢查 LLM 輸出內容。")

    return parsed_result


def ai_parsing_stage3(raw_log, prior_context=""):
    """【Stage 3: 決策生成模組 (Generation)】根據推理結果，生成或決定攻擊 Payload 執行方案"""
    print("\n[生成模組 Stage 3] 正在規劃具體攻擊 Payload 與利用鏈步驟...")
    
    # 這裡如果你有定義 get_stage3_system_prompt，請改用它
    # 目前先用 stage2 或通用範本墊底以防報錯
    try:
        from prompt import get_stage3_system_prompt
        system_prompt = get_stage3_system_prompt()
    except ImportError:
        print("[!] 警告: 未在 prompt.py 找到 get_stage3_system_prompt，暫時借用 Stage 2 模版")
        system_prompt = get_stage2_system_prompt()

    user_content = f"""{prior_context}

=== LAST EXPLOIT EXECUTION RESULT ===
{raw_log}"""
    
    return _call_ollama_and_parse_json(system_prompt, user_content, "Stage 3")

# =============================================================================
# 通用 LLM 呼叫與 JSON 清洗輔助函式
# =============================================================================

def _call_ollama_and_parse_json(system_prompt, user_content, stage_name="LLM"):
    """發送請求給 Ollama，並利用 Regex 強制清洗出合法的 Python dict"""
    raw_reply = ""
    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            options={'temperature': 0.0}
        )
        raw_reply = response['message']['content'].strip()
        
        # 剝離 Markdown Code Block (```json ... ```)
        clean_text = re.sub(r'```json|```', '', raw_reply).strip()
        
        # 擷取 JSON 區塊 { ... }
        match = re.search(r'\{.*\}', clean_text, re.DOTALL)
        clean_json_text = match.group(0) if match else clean_text
        
        # 修復數字 Key 沒有加雙引號的狀況
        clean_json_text = re.sub(r'([{,]\s*)(\d+)(\s*:) ', r'\1"\2"\3 ', clean_json_text)
        
        result = json.loads(clean_json_text)
        return result
        
    except Exception as e:
        print(f"[!] {stage_name} 模組發生未知錯誤: {e}")
        print(f"原始回傳：\n{raw_reply}\n--------------------")
        return {"status": "error", "reason": str(e), "recommended_next_steps": ["NONE"]}

# =============================================================================
# 核心資料結構與編排器
# =============================================================================

@dataclass
class IoTStageResult:
    """簡化版：記錄每一動工具執行的結果，最後用來存 MongoDB 與生報告"""
    state: str
    action_name: str       # 例如: "RUN_NMAP", "RUN_NIKTO"
    status: str = "completed" # "completed" 或 "error"
    raw_log: str = ""      # 該工具跑出來的純文字 Log
    summary: str = ""      # AI 對這段 Log 的分析總結 (JSON 裡的描述)

class IoTPipelineOrchestrator:
    def __init__(self, target_ip, toolbox, task_tree):
        self.target_ip = target_ip
        self.toolbox = toolbox
        self.task_tree = task_tree
        self.stage_results = []
        self.current_state = "stage1_recon"

        # ==========================================
        # 🧠 跨階段共享記憶體 (結構化白板)
        # ==========================================
        self.shared_memory = {
            "vendor": {},
            "discovered_services": {}, # 格式: {"80": "lighttpd 1.4.28", "53": "dnsmasq 2.41"}
            "mapped_cves": self.toolbox.mapped_cves,  # 格式: [{"cve": "CVE-2017-14491", "service": "dnsmasq", "cvss": 9.8}]
            "tried_exploits": [],      # 格式: [{"cve": "CVE-2017-14491", "status": "FAILED", "reason": "Connection reset"}]
            "recon_completed": False
        }

    def run_pipeline(self):
        print(f"\n[*] ─── 啟動門戶：IoT 非線性動態流水線 ───")
        
        self.nmap_log = self.toolbox.run_nmap()
        current_log = self.toolbox.run_nmap()
        max_turns = 5
        turn = 0
        
        while turn < max_turns:
            turn += 1
            print(f"\n[第 {turn} 輪決策] 當前系統狀態: {self.current_state}")
            
            # 1. ⚡️ 動態組裝「跨階段記憶上下文」送入 AI
            prior_context = self._build_context()
            
            # 2. 根據當前狀態派發給 AI 解析 Log
            if self.current_state == "stage1_recon":
                perception_result = ai_parsing_module(current_log, prior_context)
                self._update_stage1_memory(perception_result, raw_log=self.nmap_log)
                
            elif self.current_state == "stage2_cve_mapping":
                if "CVE-" not in current_log and "Vulnerabilities" not in current_log:
                    print("  └─ 🔄 [自動補償] 當前 Log 未含 CVE 資料，立即呼叫 RUN_NVD_LOOKUP 實體工具...")
                    current_log = self._execute_tool("RUN_NVD_LOOKUP")
                perception_result = ai_parsing_stage2(current_log, prior_context)
                self._update_stage2_memory(perception_result)
                
            elif self.current_state == "stage3_exploit":
                perception_result = ai_parsing_stage3(current_log, prior_context)
                self._update_stage3_memory(perception_result)
            
            # 3. 🧠 根據『更新後的記憶』讓 TaskTree 決策狀態轉移
            next_state = self.task_tree.update_from_perception(self.current_state, perception_result)
            
            # 取得 AI 建議的下一步行動
            recommended_action = perception_result.get("recommended_next_steps", ["NONE"])[0]
            
            # 記錄本次決策
            self.stage_results.append(IoTStageResult(
                state=self.current_state,
                action_name=recommended_action,
                raw_log=current_log,
                summary=perception_result.get("analysis_summary", "") 
            ))
            
            # 判斷是否結束
            if recommended_action == "FINISH_ALL" or next_state == "COMPLETED":
                print("[+] 任務樹回報：目標已成功拿下或已無可行路徑，終止 Pipeline。")
                break

            # 4. 🔀 狀態轉移 (在執行下一個工具前，確定當前階段)
            if next_state != self.current_state:
                print(f"[狀態轉移] {self.current_state} ➔ ➔ ➔ {next_state}")
                self.current_state = next_state

            # 5. 🛠️ 執行工具（下一個工具會拿到下一輪需要的 Log）
            print(f"[🛠️ 執行行動] 當前階段: {self.current_state} -> 準備執行工具: {recommended_action}")
            execution_result = self._execute_tool(recommended_action)
            
            print("\n================ [工具執行回傳結果] ================")
            print(execution_result[:500] + ("..." if len(execution_result) > 500 else ""))
            print("==================================================\n")
            
            # 將本次執行的結果交給下一輪
            current_log = execution_result
            print(self.shared_memory)

    def _execute_tool(self, action_name: str) -> str:
        raw_action = action_name.strip()
        print(f"\n觸發工具 (原始輸入): {raw_action}")

        # 🔄 智慧轉換：識別 LLM 或 TaskTree 產出的 NVD 查詢意圖
        if "get_nvd" in raw_action.lower() or "RUN_NVD_LOOKUP" in raw_action:
            action_name = "RUN_NVD_LOOKUP"
        elif "nikto" in raw_action.lower() or "RUN_NIKTO" in raw_action:
            action_name = "RUN_NIKTO"
        elif "exploit" in raw_action.lower() or "RUN_EXPLOIT_DLINK" in raw_action:
            action_name = "RUN_EXPLOIT_DLINK"

        # -----------------------------------
        log = ""
        if action_name == "RUN_NIKTO":
            print("[+] 正在背景執行 Nikto 網頁漏洞掃描，請稍候...")
            log = self.toolbox.run_nikto()
            print(f"[+] Nikto 執行完畢，成功獲取 {len(log)} 字元的日誌資料。")
            
            banner_match = re.search(r"\+\s*Server:\s*([a-zA-Z0-9\-_]+)/([\d\.]+)", log)
            if banner_match:
                product = banner_match.group(1)
                version = banner_match.group(2)
                
                # 1. 動態從傳入的指令參數抓取 Port (若無指定則預設 "80")
                target_raw_port = "80"
                if "action_params" in locals() and action_params:
                    target_raw_port = str(action_params[0])
                
                # 2. 透過 _normalize_port 動態轉換成標準格式 (如 "80/tcp" 或 "8080/tcp")
                target_port = self._normalize_port(target_raw_port)
                
                # 3. 動態更新記憶體
                if target_port not in self.shared_memory["discovered_services"]:
                    self.shared_memory["discovered_services"][target_port] = {}
                
                self.shared_memory["discovered_services"][target_port]["name"] = product
                self.shared_memory["discovered_services"][target_port]["version"] = version
                print(f"[+] [記憶體即時同步] Port {target_port} 已順利更新為 '{product} {version}'")

        elif action_name == "RUN_NVD_LOOKUP":
            print("[🔍 實體工具呼叫] 正在向 NVD 資料庫檢索已知漏洞...")
            services = self.shared_memory.get("discovered_services", {})
            nvd_markdown_report = self.toolbox.run_nvd_lookup(services)
            self.shared_memory["discovered_services"] = services
            return nvd_markdown_report  # <-- 這會直接回傳 Markdown 格式的 CVE 報告！

        elif action_name == "RUN_CURL":
            # 1. 解析目標 Port (預設 80)
            target_port_str = "80/tcp"

            # (A) 優先讀取 AI 指令帶入的參數 (例如: RUN_CURL 8080)
            if "action_params" in locals() and action_params:
                target_port_str = self._normalize_port(str(action_params[0]))

            # (B) 若無參數，從 Shared Memory 動態尋找 Web 服務 Port
            else:
                services = self.shared_memory.get("discovered_services", {})
                for port_key, info in services.items():
                    svc_name = str(info.get("name", "")).lower()
                    if (
                        "http" in svc_name
                        or "web" in svc_name
                        or port_key
                        in ["80/tcp", "443/tcp", "8080/tcp", "8443/tcp"]
                    ):
                        target_port_str = port_key
                        break

            # 2. 提取整數 Port 數字 (如從 "8080/tcp" 提取出整數 8080)
            port_num = (
                int(target_port_str.split("/")[0])
                if "/" in target_port_str
                else int(target_port_str)
            )

            print(
                f"[+] 正在背景對 Port {port_num} 執行 Curl HTTP 探測，請稍候..."
            )

            # 3. 呼叫 Toolbox 並傳入正確型別的 port
            curl_res = self.toolbox.run_curl(port=port_num)

            # 4. 處理回傳結果：將 dict 格式化為 LLM 感知模組可讀的 Raw Log 字串
            if isinstance(curl_res, dict):
                if curl_res.get("status") == "success":
                    headers_text = curl_res.get("headers", "")
                    log = f"=== Curl Response Headers (Port {port_num}) ===\n{headers_text}\n\n=== Body Snippet ===\n{curl_res.get('body_snippet', '')}"

                    # 自動更新 Shared Memory 中的 Server Banner (如果存在)
                    banner_match = re.search(
                        r"[Ss]erver:\s*([a-zA-Z0-9\-_]+)[/\s]([\d\.]+)",
                        headers_text,
                    )
                    if banner_match:
                        product, version = (
                            banner_match.group(1),
                            banner_match.group(2),
                        )
                        normalized_key = self._normalize_port(
                            str(port_num) + "/tcp"
                        )

                        if (
                            normalized_key
                            not in self.shared_memory["discovered_services"]
                        ):
                            self.shared_memory["discovered_services"][
                                normalized_key
                            ] = {}

                        self.shared_memory["discovered_services"][
                            normalized_key
                        ]["name"] = product
                        self.shared_memory["discovered_services"][
                            normalized_key
                        ]["version"] = version
                        print(
                            f"[+] [記憶體即時同步] Port {normalized_key}"
                            f" 已順利更新為 '{product} {version}'"
                        )
                else:
                    log = (
                        f"[Curl Error] Target Port {port_num} -"
                        f" {curl_res.get('error', 'Unknown Error')}"
                    )
            else:
                log = str(curl_res)

            return log

        elif action_name == "RUN_EXPLOIT_DLINK":
            print("[🔥 關鍵行動] 偵測到漏洞，正在向 D-Link 模擬相機發送 CVE 攻擊 Payload...")
            log = self.toolbox.run_exploit_dlink()
            print("[+] 攻擊腳本執行完畢，已將回傳日誌回傳給大腦。")

        elif action_name == "SEARCH_RAG_POC":
            print("[🔍 實體工具呼叫] 正在向 RAG 資料庫檢索相關漏洞...")
            print(f"\n[當前 Share Memory 資料]")
            util.pretty_print_json(self.shared_memory)
            query = self.shared_memory.get("rag_query", "")
            print(query)
            
            if not query:
                print("[Error] 獲取 RAG Query 失敗")
            else:
                log = self.toolbox.search_rag_poc(query)
                try:
                    # 💡 修正 1：用 json.loads() 解析字串
                    if isinstance(log, str):
                        cve_list = json.loads(log)
                    else:
                        cve_list = log  # 預防萬一本來就是 list/dict

                    # 💡 修正 2：正確將結果更新回 shared_memory 內的 mapped_cves 或對應欄位
                    for cve in cve_list:
                        # 範例：如果想把找到的 CVE 塞進 mapped_cves 裡面
                        if cve not in self.shared_memory["mapped_cves"]:
                            self.shared_memory["mapped_cves"].append(cve)
                except Exception as e:
                    print(f"[SEARCH RAG POC ERROR] {e}")

        else:
            print("ℹ️ [Tool Executor] 當前無須執行實體工具，跳過工具呼叫，直接進入下一輪決策。")
            return "No tool executed."

        print("[+] ⏳ 啟動 IoT 設備冷卻保護，等待 3 秒鐘讓網路連線池復原...")

        time.sleep(3)
        return log
    
    def _get_tool_history(self) -> list:
        """從 stage_results 中萃取出所有使用過的工具名稱"""
        return [res.action_name for res in self.stage_results if res.action_name and res.action_name != "NONE"]

    def _build_context(self) -> str:
        """
        將『結構化記憶體』與『已使用工具歷史』轉換為易讀的 Markdown 文字
        """
        context_lines = ["=== SYSTEM SHARED MEMORY (PAST KNOWLEDGE) ==="]
        
        # 1. 注入已確定的服務與版本資訊
        context_lines.append("[Discovered Services & Versions]:")
        if self.shared_memory["discovered_services"]:
            for port, info in self.shared_memory["discovered_services"].items():
                context_lines.append(
                    f"  - Port {port}: {info.get('name', 'Unknown')} "
                    f"(Version: {info.get('version', 'Unknown')})"
                )
        else:
            context_lines.append("  - No verified services yet.")
            
        # 2. 注入工具使用歷史（對應你的規則 10：ANTI-REPETITION）
        tool_history = self._get_tool_history()
        context_lines.append("\n[Recently Executed Tools / History]:")
        if tool_history:
            # 這裡可以運用前面提過的技巧，只取最近 3 個避免 Prompt 太長，或全數列出
            recent_tools = tool_history[-3:]
            context_lines.append(f"  - Recently used: {recent_tools}")
        else:
            context_lines.append("  - No tools executed yet.")

        # 3. 注入 Stage 2 比對出的 CVE 成果
        if self.shared_memory["mapped_cves"]:
            context_lines.append("\n[Mapped Known Vulnerabilities (CVEs)]:")
            for cve in self.shared_memory["mapped_cves"]:
                context_lines.append(
                    f"  - {cve['cve_id']} on {cve['service']} "
                    f"(CVSS: {cve['score']}) -> {cve.get('description', '')}"
                )

        # 4. 注入失敗的嘗試防呆
        if self.shared_memory["tried_exploits"]:
            context_lines.append("\n[🚨 Warning: Previously Failed Exploits - DO NOT RETRY THESE]:")
            for fail in self.shared_memory["tried_exploits"]:
                context_lines.append(f"  - Exploit {fail['cve']} FAILED. Reason: {fail['reason']}")

        return "\n".join(context_lines)

    def _normalize_port(self, port_raw, default_proto="tcp") -> str:
        """統一轉成 <port>/<protocol> 格式 (如 '80/tcp', '67/udp')"""
        s = str(port_raw).strip().lower()
        if "/" not in s:
            return f"{s}/{default_proto}"
        return s

    def _update_stage1_memory(self, perception_result: dict, raw_log: str = ""):
        # 1. 第一層保險：Regex 自動解析原始 Nmap 日誌
        if raw_log:
            pattern = r"(\d+)/(tcp|udp)\s+(open\|filtered|open)\s+([\w\-\?\/\(\)]+)(?:\s+(.+))?"

            for line in raw_log.splitlines():
                line_str = line.strip()
                match = re.search(pattern, line_str)
                if match:
                    port, proto, state, service, version = match.groups()
                    port_key = f"{port}/{proto}"

                    clean_service = service.replace("?", "").strip()
                    clean_version = (
                        version.strip()
                        if (version and "Nmap scan report" not in version)
                        else "unknown"
                    )

                    current_info = self.shared_memory["discovered_services"].get(port_key, {})
                    current_version = current_info.get("version", "unknown")

                    if (
                        port_key not in self.shared_memory["discovered_services"]
                        or (clean_version != "unknown" and current_version == "unknown")
                    ):
                        self.shared_memory["discovered_services"][port_key] = {
                            "name": clean_service,
                            "version": clean_version,
                        }

        # 💡 2. 解析 LLM 回傳的全域 Vendor 廠商資訊 (例如 "D-Link Systems")
        extracted_vendor = perception_result.get("vendor", perception_result.get("device_vendor", ""))
        if extracted_vendor and extracted_vendor.lower() != "unknown":
            self.shared_memory["vendor"] = extracted_vendor

        # 3. 第二層保險：解析 LLM (Qwen2.5-Coder) 回傳的 JSON 服務列表
        services = perception_result.get("services", {})

        for port, info in services.items():
            port_str = self._normalize_port(port)

            if isinstance(info, dict):
                service_name = info.get("service", info.get("name", "unknown"))
                service_version = info.get("version", "unknown")
            else:
                service_name = str(info)
                service_version = "unknown"

            current_node = self.shared_memory["discovered_services"].get(port_str, {})
            final_name = (
                service_name
                if service_name != "unknown"
                else current_node.get("name", "unknown")
            )
            final_version = (
                service_version
                if service_version != "unknown"
                else current_node.get("version", "unknown")
            )

            self.shared_memory["discovered_services"][port_str] = {
                "name": final_name,
                "version": final_version,
            }

        # 4. 同步到 TaskTree
        if hasattr(self, "task_tree"):
            self.task_tree.scanned_ports = {
                port: {"service": info["name"], "version": info["version"]}
                for port, info in self.shared_memory["discovered_services"].items()
            }
            # 如果 TaskTree 也支援記錄 vendor，同步寫入
            if hasattr(self.task_tree, "vendor"):
                self.task_tree.vendor = self.shared_memory["vendor"]

    def _update_stage2_memory(self, perception_result: dict):
        """解析 Stage 2 的 JSON，更新漏洞評估與目標選擇記憶"""
        if not isinstance(perception_result, dict):
            return
        
        stage2_info = perception_result.get("stage2_status", {})
    
        # 1. 保存/更新比對出的 CVE 清單
        matched = stage2_info.get("matched_cves", [])
        if matched:
            self.shared_memory["mapped_cves"] = matched
        
        #2. 存入 Stage 2 最終精選的「當前焦點 CVE」與「推理決策」
        if "selected_target_cve" in stage2_info:
            self.shared_memory["current_target_cve"] = stage2_info.get("selected_target_cve")
            self.shared_memory["target_reasoning"] = stage2_info.get("reason", "")
            self.shared_memory["rag_query"] = stage2_info.get("rag_search_query", "")

    def _update_stage3_memory(self, perception_result: dict):
        """解析 Stage 3 的 JSON，如果 Exploit 失敗，記錄失敗原因"""
        # 假設 Stage 3 回傳攻擊狀態
        exploit_status = perception_result.get("exploit_status", {})
        if exploit_status.get("result") == "FAILED":
            self.shared_memory["tried_exploits"].append({
                "cve": exploit_status.get("targeted_cve"),
                "reason": exploit_status.get("error_message", "Unknown execution error")
            })

    def _save_to_db_and_report(self):
        """最後整合資料庫與生報告的邏輯"""
        # 可以在這裡寫寫入 MongoDB 的 Code
        pass
    
if __name__ == "__main__":
    print("[*] 正在初始化 ai_agent 主程式 ...")
    
    # 1. 設定目標 IP (可以寫死或從環境變數拿)
    TARGET_IP = "192.168.0.1" 
    
    # 2. 實體化雙手（工具箱）與記憶（任務樹）
    toolbox = PentestToolbox(target_ip=TARGET_IP)
    task_tree = TaskTree()  
    
    # 3. 將控制權交給流水線編排器
    orchestrator = IoTPipelineOrchestrator(
        target_ip=TARGET_IP, 
        toolbox=toolbox, 
        task_tree=task_tree
    )
    
    # 4. 🚀 啟動全自動智慧滲透流水線
    orchestrator.run_pipeline()

    # orchestrator._execute_tool("SEARCH_RAG_POC")
    
    print("\n[+] 主程式安全退出。")
