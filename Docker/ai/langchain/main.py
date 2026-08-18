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
    
    if "PORT STATE SERVICE" in str(raw_log) or "/tcp" in str(raw_log):
        cleaned_lines = []
        for line in raw_log.split('\n'):
            if "/tcp" in line or "/udp" in line or "PORT" in line:
                cleaned_lines.append(line.strip())
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
            "discovered_services": {}, # 格式: {"80": "lighttpd 1.4.28", "53": "dnsmasq 2.41"}
            "mapped_cves": self.toolbox.mapped_cves,  # 格式: [{"cve": "CVE-2017-14491", "service": "dnsmasq", "cvss": 9.8}]
            "tried_exploits": [],      # 格式: [{"cve": "CVE-2017-14491", "status": "FAILED", "reason": "Connection reset"}]
            "recon_completed": False
        }

    def run_pipeline(self):
        print(f"\n[*] ─── 啟動門戶：IoT 非線性動態流水線 ───")
        
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
                self._update_stage1_memory(perception_result)
                
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

    def _update_stage1_memory(self, perception_result: dict):
        """解析 Stage 1 的 JSON，更新服務與版本記憶"""
        services = perception_result.get("services", {})
        open_ports = perception_result.get("open_ports", [])

        # 1. 優先處理 services 裡帶有完整協定 (如 /udp, /tcp) 的 Key
        for port, info in services.items():
            port_str = self._normalize_port(port)

            if isinstance(info, dict):
                service_name = info.get("service", info.get("name", "unknown"))
                service_version = info.get("version", "unknown")
            else:
                service_name = str(info)
                service_version = "unknown"

            current_node = self.shared_memory["discovered_services"].get(port_str, {})
            final_name = service_name if service_name != "unknown" else current_node.get("name", "unknown")
            final_version = service_version if service_version != "unknown" else current_node.get("version", "unknown")

            self.shared_memory["discovered_services"][port_str] = {
                "name": final_name,
                "version": final_version
            }

        # 2. 處理 open_ports：若埠號已被 services 建檔（無論 tcp/udp），就不再重複補建
        for p in open_ports:
            p_str = str(p).strip().lower()
            # 檢查目前記憶體中是否已有該 Port (例如已存在 "67/udp" 或 "80/tcp")
            already_exists = any(
                existing_key == p_str or existing_key.startswith(f"{p_str}/")
                for existing_key in self.shared_memory["discovered_services"]
            )
            if not already_exists:
                port_str = self._normalize_port(p_str)
                self.shared_memory["discovered_services"][port_str] = {
                    "name": "unknown",
                    "version": "unknown"
                }

        # 3. 同步到 TaskTree
        if hasattr(self, "task_tree"):
            self.task_tree.scanned_ports = {
                port: {
                    "service": info["name"],
                    "version": info["version"]
                }
                for port, info in self.shared_memory["discovered_services"].items()
            }

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
