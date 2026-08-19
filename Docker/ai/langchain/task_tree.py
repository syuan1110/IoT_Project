import json
from datetime import datetime

class TaskTree:
    def __init__(self):
        self.target = None
        self.status = "initialized"
        self.created_at = datetime.now().isoformat()
        self.stage2_decision_made = False
        
        # 1. 階段閘門管理
        self.stages = {
            "stage1_recon": "todo",          # 資產與服務偵察
            "stage2_cve_mapping": "todo",    # NVD 漏洞查詢與戰術思考
            "stage3_exploit": "todo",        # 漏洞利用
            "stage4_report": "todo"          # 報告生成
        }
        
        self.scanned_ports = {} 
        self.global_vectors = []
        self.latest_recommended_steps = []
        self.vendor = []

    def update_from_perception(self, current_stage: str, perception_json: dict) -> str:
        self.target = perception_json.get("target", self.target)
        self.latest_recommended_steps = perception_json.get("recommended_next_steps", [])
        
        # 💡 新增：自動更新與維護 TaskTree 中的 vendor 屬性
        extracted_vendor = perception_json.get("vendor", perception_json.get("device_vendor", ""))
        if extracted_vendor and extracted_vendor.lower() != "unknown":
            self.vendor = extracted_vendor

        new_ports = perception_json.get("open_ports", [])
        services_map = perception_json.get("services", {})
        vectors = perception_json.get("potential_attack_vectors", [])
        
        for v in vectors:
            if v not in self.global_vectors:
                self.global_vectors.append(v)

        for port in new_ports:
            port_str = str(port)
            ai_port_info = services_map.get(port_str, {})
            
            if isinstance(ai_port_info, str):
                ai_service, ai_version = ai_port_info, "unknown"
            else:
                ai_service = ai_port_info.get("service", "unknown")
                ai_version = ai_port_info.get("version", "unknown")

            if port_str not in self.scanned_ports:
                self.scanned_ports[port_str] = {
                    "service": ai_service,
                    "version": ai_version,
                    "nvd_searched": False,  
                    "is_exploited": False,
                    "discovered_at": datetime.now().isoformat()
                }
            else:
                current_node = self.scanned_ports[port_str]
                if ai_service != "unknown":
                    current_node["service"] = ai_service
                if current_node.get("version", "unknown") == "unknown" and ai_version != "unknown":
                    current_node["version"] = ai_version

        # 1. 評估閘門狀態
        self._auto_eval_stage_status(current_stage)

        # 2. 狀態切換
        next_stage = current_stage
        
        if current_stage == "stage1_recon" and self.stages.get("stage1_recon") == "completed":
            print("\n[+ TaskTree Gate] ⚙️【Stage 1 完工】資產偵察全數完成，推進至 Stage 2 (CVE Mapping & NVD 查詢)")
            self.stages["stage2_cve_mapping"] = "running"
            next_stage = "stage2_cve_mapping"
            
        elif current_stage == "stage2_cve_mapping" and self.stages.get("stage2_cve_mapping") == "completed":
            print("\n[+ TaskTree Gate] ⚙️【Stage 2 完工】CVE 對照與戰術選定完成，推進至 Stage 3 (Exploit)")
            self.stages["stage3_exploit"] = "running"
            next_stage = "stage3_exploit"
            
        return next_stage

    def _auto_eval_stage_status(self, current_stage: str):
        # --- Stage 1: 純資產偵察 ---
        if current_stage == "stage1_recon":
            has_ports = len(self.scanned_ports) > 0

            all_ports_identified = (
                has_ports and 
                all(
                    info.get("service", "unknown") != "unknown" and 
                    info.get("version", "unknown") != "unknown"
                    for info in self.scanned_ports.values()
                )
            )
            
            ai_said_finish = (
                bool(self.latest_recommended_steps) and 
                any(str(move).upper() in ["NONE", "FINISH", "STOP", "NO_TOOL"] for move in self.latest_recommended_steps)
            )

            # 只有在「全部識別完畢」或者「AI 主動宣告完工」時，才允許通過 Stage 1！
            if all_ports_identified or ai_said_finish:
                self.stages["stage1_recon"] = "completed"

        # --- Stage 2: NVD 查詢與戰術思考 ---
        elif current_stage == "stage2_cve_mapping":
            # 條件：所有埠口都標記為已查詢過 NVD (或外部邏輯已完成 CVE 批次比對)
            # 且 LLM 完成了選定策略 (stage2_decision_made = True)
            if self.stage2_decision_made:
                self.stages["stage2_cve_mapping"] = "completed"

        # --- Stage 3: 漏洞利用 ---
        elif current_stage == "stage3_exploit":
            if any(info.get("is_exploited", False) for info in self.scanned_ports.values()):
                self.stages["stage3_exploit"] = "completed"

    def mark_stage2_decision_done(self):
        self.stage2_decision_made = True
        self._auto_eval_stage_status("stage2_cve_mapping")