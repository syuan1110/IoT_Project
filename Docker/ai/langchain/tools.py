import subprocess
import time
import re
import get_nvd

class PentestToolbox:
    def __init__(self, target_ip, db_client=None):
        """
        初始化工具箱
        :param target_ip: 要攻擊或掃描的目標 IoT 設備 IP
        :param db_client: MongoDB 的連線實例（選填，之後 main.py 傳進來）
        """
        self.target_ip = target_ip
        self.db = db_client
        self.mapped_cves = []       # 共享記憶體：儲存經 NVD 查詢並篩選後的結構化 CVE 漏洞清單

    def run_nmap(self):
        """一：執行 TCP 安全盲掃 (-sT 避開 raw socket 權限與 QEMU slirp 問題)

        二：若 TCP 53 開放，單獨做 -sV 版本偵測
        三：針對核心 UDP 服務先進行快速探測，過濾出開放的 Port 後再追加 -sV 精準偵測
        """
        raw_log = ""

        # 1. TCP 掃描：改用 -sT (Connect scan)，不需要 root 權限，且對 QEMU 網路相容性最好
        command = [
            "nmap",
            "-sT",
            "-F",
            "--max-rate",
            "50",
            "-T3",
            self.target_ip,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            raw_log += result.stdout
            if result.stderr:
                raw_log += f"\n[TCP Stderr]\n{result.stderr}"
        except Exception as e:
            raw_log += f"\n[TCP Scan Failed]: {str(e)}"

        # 2. Port 53 TCP 精準版本偵測 (改用正則表達式防誤判)
        if re.search(r"53/tcp\s+open", raw_log):
            targeted_53_command = [
                "nmap",
                "-sT",
                "-p",
                "53",
                "-sV",
                "--version-intensity",
                "5",
                self.target_ip,
            ]
            try:
                res_53 = subprocess.run(
                    targeted_53_command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                raw_log += f"\n\n=== Targeted Port 53 Service Detection Result ===\n{res_53.stdout}"
            except Exception as e:
                raw_log += f"\n[Port 53 Scan Failed]: {str(e)}"

        # 3. 關鍵 UDP Port 快速篩選
        target_udp_ports = "53,67,69,161,1900,5000,5351"
        udp_fast_command = [
            "nmap",
            "-sU",
            "-p",
            target_udp_ports,
            "--max-rate",
            "30",
            "--max-retries",
            "1",
            self.target_ip,
        ]

        udp_scan_stdout = ""
        try:
            res_udp = subprocess.run(
                udp_fast_command,
                capture_output=True,
                text=True,
                check=False,
                timeout=45,
            )
            udp_scan_stdout = res_udp.stdout
            raw_log += f"\n\n=== UDP Quick Scan Result ===\n{udp_scan_stdout}"
        except Exception as e:
            raw_log += f"\n[UDP Quick Scan Failed]: {str(e)}"

        # 4. 【新增】對有回應的 UDP Port 進行 -sV 精準版本偵測
        # 抓取輸出中狀態為 open 或 open|filtered 的 UDP Port
        open_udp_ports = re.findall(
            r"(\d+)/udp\s+(?:open|open\|filtered)", udp_scan_stdout
        )

        if open_udp_ports:
            ports_str = ",".join(open_udp_ports)
            udp_sv_command = [
                "nmap",
                "-sU",
                "-sV",
                "--version-intensity",
                "4",
                "-p",
                ports_str,
                "--max-retries",
                "1",
                self.target_ip,
            ]
            try:
                res_udp_sv = subprocess.run(
                    udp_sv_command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,  
                )
                raw_log += f"\n\n=== UDP Detailed Service/Version Detection Result ===\n{res_udp_sv.stdout}"
            except Exception as e:
                raw_log += f"\n[UDP Version Scan Failed]: {str(e)}"

        return raw_log

    def run_nikto(self):
        """Nikto 網頁伺服器版本與潛在漏洞掃描，並自動提煉 Server Banner"""
        print(
            f"[Toolbox] 啟動 Nikto 深入探測網頁版本 -> 目標: {self.target_ip}"
        )

        # 💡 修正 -Pause 語法，並加入 -Tuning b (僅掃描 Banner/版本) 與 -maxtime
        command = [
            "nikto",
            "-h", f"http://{self.target_ip}",
            "-Pause", "1",        # 每次請求間隔 1 秒，保護輕量級 Web Server
            "-Tuning", "b",       # 僅進行 Software Version 識別，大幅減少 Request 數量
            "-maxtime", "60s"     # 限制 Nikto 內部最大執行時間 60 秒
        ]

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=120
            )
            raw_log = result.stdout
            if result.stderr:
                raw_log += f"\n[Stderr]\n{result.stderr}"

            # 💡 使用正則表達式自動抓取 Nikto 輸出的 Server Banner
            # 匹配範例: "+ Server: lighttpd/1.4.28" 或 "+ Server: Apache/2.4.41"
            banner_match = re.search(
                r"\+\s*Server:\s*([a-zA-Z0-9\-_]+)/([\d\.]+)", raw_log
            )

            extracted_info = ""
            if banner_match:
                product = banner_match.group(1)  # 例如: lighttpd
                version = banner_match.group(2)  # 例如: 1.4.28
                extracted_info = f"\n\n[系統自動解析] 偵測到服務 Banner: Product='{product}', Version='{version}'"
                extracted_info += f"\n建議執行的 NVD 查詢指令: python3 get_nvd.py {product} {version}"

            return raw_log + extracted_info

        except subprocess.TimeoutExpired:
            return "[!] Nikto 掃描因超過時間限制結束，返回部分擷取日誌。"
        except Exception as e:
            return f"[Nikto Error] {str(e)}"

    def run_nvd_lookup(self, discovered_services):
        """
        NVD 漏洞自動批次查詢工具
        :param discovered_services: 從共享記憶體中拿到的發現服務字典 (如 {"53": {"name": "dnsmasq", "version": "2.41", "nvd_searched": False}})
        :return: 易於餵給 Stage 2 AI 的批次 Markdown 格式漏洞分析
        """
        print(f"[Toolbox] 啟動 NVD 漏洞批次過濾與查詢機制...")
        
        if not discovered_services:
            return "### [NVD 查詢結果]\n目前沒有任何已發現的服務資產，無法進行 NVD 查詢。"
        
        all_reports = []
        
        # 1. 遍歷所有通訊埠與服務
        for port, info in discovered_services.items():
            product_name = info.get("name")
            target_version = info.get("version", "unknown")
            is_searched = info.get("nvd_searched", False)
            
            # 防呆檢查
            if not product_name or target_version.lower() == "unknown" or not target_version.strip():
                continue
                
            # 2. 若之前已查詢過，直接從 mapped_cves 快取讀取，並加入強烈防鬼打牆提示
            if is_searched:
                existing_cves = [c for c in self.mapped_cves if str(c.get("port")) == str(port)]
                output = [f"## ⚠️ [系統提示] Port {port} ({product_name} {target_version}) 已經完成過 NVD 查詢！"]
                output.append("📌 **警告：請勿重複執行此服務的 NVD 查詢，請立刻進行下一個服務的偵察或進入下一階段攻擊規劃。**\n")
                
                all_reports.append("\n".join(output))
                continue # 跳過對 API 的重複請求
                
            print(f"[Toolbox] 發現未查詢資產 -> Port {port}: {product_name} ({target_version}) 正在連線 NVD...")
            
            try:
                # 3. 呼叫核心 API
                vulnerability_list = get_nvd.get_vulnerability_data(product_name, target_version)
                
                # 標記為已查詢，防止下一輪又重複呼叫
                info["nvd_searched"] = True
                
                output = []
                output.append(f"## 🔍 NVD 漏洞查詢結果: {product_name} ({target_version}) [Port: {port}]")
                
                if not vulnerability_list:
                    output.append(f"- 在 NVD 中未發現任何與此版本直接相符的已知 CVE 漏洞。\n")
                    all_reports.append("\n".join(output))
                    continue
                
                output.append(f"系統已自動過濾版本不符的雜訊，以下為該產品目前版本確實受影響的漏洞 (共 {len(vulnerability_list)} 個，已排序並限制前 5 個以防 Token 爆炸)：\n")
                
                # 依照 CVSS 分數由高到低排序
                vulnerability_list.sort(key=lambda x: x.get("cvss", {}).get("score", 0.0) or 0.0, reverse=True)

                # 4. 批次處理與記憶陣列（mapped_cves）同步寫入
                for idx, item in enumerate(vulnerability_list[:5], start=1):
                    cve_id = item.get("cveID")
                    cvss_info = item.get("cvss", {})
                    score = cvss_info.get("score", 0.0) or 0.0
                    severity = cvss_info.get("severity", "UNKNOWN")
                    cwes = item.get("cwe", [])
                    desc = item.get("description", "無詳細描述。")

                    # 構造統一標準的 CVE 物件（存進系統內部狀態，保持資料完整）
                    cve_obj = {
                        "cve_id": cve_id,
                        "service": product_name,
                        "version": target_version,
                        "port": str(port),
                        "severity": severity,
                        "score": score,
                        "cvss": score,
                        "cwes": cwes,
                        "description": desc,
                        "summary": desc[:100] + "..." if len(desc) > 100 else desc, # 精簡版摘要
                    }

                    # 防止重複寫入 mapped_cves (比對 CVE ID 與 Port)
                    if not any(e.get("cve_id") == cve_id and str(e.get("port")) == str(port) for e in self.mapped_cves):
                        self.mapped_cves.append(cve_obj)

                    # 精簡 Description 給 LLM 閱讀 (截斷前 100 個字元)
                    clean_desc = desc.replace("\n", " ")
                    short_desc = (clean_desc[:100] + "...") if len(clean_desc) > 100 else clean_desc

                    # 拼接極簡 Bullet Point 輸出給 LLM (省略 CPE, CVSS Vector, 重度 Markdown 標題)
                    cwe_str = f" [CWE: {', '.join(cwes)}]" if cwes else ""
                    output.append(f"- {cve_id} (Score: {score} {severity}){cwe_str}: {short_desc}")

                output.append("") # 尾部留空行
                    
                all_reports.append("\n".join(output))
                
            except Exception as e:
                all_reports.append(f"### ❌ [NVD 查詢錯誤] 查詢 {product_name} ({target_version}) 時發生異常: {str(e)}")
        
        # 5. 回傳最終整合報告
        if not all_reports:
            return "### [NVD 查詢結果]\n所有已知服務皆已完成過 NVD 歷史查詢，且目前無新資產資訊。"
            
        return "\n\n---\n\n".join(all_reports)

    def run_dirbuster(self):
        """目錄爆破工具"""
        print(f"[Toolbox] 啟動目錄掃描 -> 目標: {self.target_ip}")
        raw_log = "假設這是 dirb 噴出來的純文字 Log..."
        return raw_log

    def run_exploit_dlink(self):
        """針對 D-Link 模擬韌體的特定 Exploit 攻擊"""
        print(f"[Toolbox] 針對 D-Link 模擬環境發動 Exploit 攻擊 -> 目標: {self.target_ip}")
        raw_log = "漏洞利用成功！取得管理者 Shell Log..."
        return raw_log

    def search_rag_poc(self, query: str) -> str:
        print(f"[🔍 Docker CLI RAG] 正在向 RAG 容器傳遞查詢: {query}")
        try:
            # 透過 docker exec 執行你剛寫好的 RAG 程式
            docker_cmd = [
                "docker", "exec", "-i", "RAG", 
                "python3", "RAG_search.py", query
            ]
            
            result = subprocess.run(
                docker_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return f"RAG Error: {result.stderr.strip()}"
        except Exception as e:
            return f"Failed to execute RAG container: {str(e)}"

# ─────────────── (測試用) ───────────────
# if __name__ == "__main__":
#     # 在這裡把你的韌體 IP 傳進去
#    my_firmware_ip = "192.168.0.1"
    
#     # 建立工具箱實體
#    toolbox = PentestToolbox(target_ip=my_firmware_ip)
    
#     # 測試執行 Nmap 看看能不能掃到 D-Link 韌體
#    test_result = toolbox.run_RAG_search("Dlink")
    
#    print("\n--- Nmap 掃描 D-Link 韌體的 Raw Log 如下 ---")
#    print(test_result)
