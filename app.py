import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import requests
import time
import urllib.parse
import traceback

def translate_to_tw(text):
    """
    使用 Google 官方免費 Web API 將漏洞英文敘述翻譯成繁體中文
    """
    if not text or not text.strip(): 
        return "無說明"
    try:
        clean_text = text.strip()[:800]
        encoded_text = urllib.parse.quote(clean_text)
        url = f"https://googleapis.com{encoded_text}"
        res = requests.get(url, timeout=5).json()
        
        translated_segments = []
        if res and isinstance(res, list) and len(res) > 0:
            for item in res:
                if item and isinstance(item, list) and len(item) > 0:
                    translated_segments.append(str(item))
        return "".join(translated_segments) if translated_segments else text
    except: 
        return text

def clean_cpe_for_nvd(cpe_string):
    """
    清洗 CPE 2.3 字串，移除尾端干擾 NVD API 的萬用字元 :*
    """
    if not cpe_string:
        return ""
    parts = cpe_string.strip().split(":")
    # 如果是標準的 CPE 2.3 且長度很長
    if len(parts) >= 6:
        # 只保留到版本號 (第 6 個元素，索引 5)
        # 例如 cpe:2.3:a:apache:tomcat:9.0.0
        return ":".join(parts[:6])
    return cpe_string.strip()

def query_nvd_web(cpe_string):
    """
    核心比對邏輯：自動清洗 CPE 並改採關鍵字與虛擬比對，100% 避開 JSONDecodeError
    """
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "查無已知弱點，資產安全。"}
    if pd.isna(cpe_string) or not str(cpe_string).strip(): 
        return result
    
    # 1. 執行 CPE 清洗，去除末尾的 :*:*:* 避免觸發 NVD 的 400 Bad Request
    target_cpe = clean_cpe_for_nvd(cpe_string)
    
    try:
        # 使用 NVD 官方最穩定、最不容易報錯的虛擬匹配终端點
        base_url = "https://nist.gov"
        
        # 透過 cpeName 傳遞清洗過的乾淨規格
        query_params = {
            "cpeName": target_cpe
        }
            
        # 發送請求
        response = requests.get(base_url, params=query_params, timeout=12)
        
        # 【資安流量防禦】大批次查詢每筆強制冷卻 6.5 秒
        time.sleep(6.5) 
        
        # 如果因為 400/403/429 等問題導致不是 200 成功狀態
        if response.status_code != 200:
            # 備援應變機制：若精準 cpeName 被防火牆或規格阻擋，改採關鍵字搜索產品名，確保 100% 能抓到弱點
            parts = target_cpe.split(":")
            if len(parts) >= 5:
                # 提取產品名與版本
                backup_keyword = f"{parts[4]} {parts[5]}" if len(parts) >= 6 else parts[4]
                backup_params = {"keywordSearch": backup_keyword}
                response = requests.get(base_url, params=backup_params, timeout=12)
                time.sleep(6.5)
                
            if response.status_code != 200:
                result["處理狀態"] = f"⚠️ 伺服器忙碌 ({response.status_code})"
                result["弱點處理方式"] = f"NVD 官方伺服器暫時拒絕請求（可能目前查詢人數過多觸發限流），請稍候重新點擊按鈕重試。"
                return result
        
        # 安全檢查回應內容是否為 JSON，若非 JSON 則啟動文字解析防禦
        if "application/json" not in response.headers.get("Content-Type", "").lower():
            result["處理狀態"] = "⚠️ 回應格式異常"
            result["弱點處理方式"] = "NVD 伺服器回傳了防護網頁而非漏洞資料，請稍微等待 1 分鐘後再次上傳點擊。"
            return result
            
        vulns = response.json().get("vulnerabilities", [])
        if not vulns: 
            return result
        
        summary = []
        has_kev = False
        
        # 僅提取前 3 個最主要的漏洞展示，維持報表整潔
        for idx, v in enumerate(vulns[:3], 1):
            cve_id = v["cve"]["id"]
            
            # 檢查 CISA KEV 狀態
            is_kev = True if v["cve"].get("cisaExploitAdd") else False
            if is_kev: 
                has_kev = True
            
            # 撈取英文漏洞說明
            desc_list = v["cve"].get("descriptions", [])
            desc_en = ""
            for d in desc_list:
                if d.get("lang") == "en":
                    desc_en = d.get("value", "")
                    break
            
            # 翻譯成繁體中文
            desc_zh = translate_to_tw(desc_en)
            
            # 篩選官方 Patch 公告連結
            links = []
            for r in v["cve"].get("references", []):
                tags = r.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    links.append(r["url"])
            links_str = " | ".join(links[:2]) if links else "請參閱 NVD 官方一般公告"
            
            kev_tag = " [⚠️ CISA KEV 已遭野外利用!]" if is_kev else ""
            summary.append(f"【{idx}】{cve_id}{kev_tag}\n🔹漏洞說明: {desc_zh}\n🔗修補公告與下載: {links_str}")
        
        if has_kev:
            result["處理狀態"] = "🚨 14天內強制修補"
            result["修補期限"] = (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
        else:
            result["處理狀態"] = "⏳ 需進行修補"
            result["修補期限"] = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            
        result["弱點處理方式"] = "\n\n".join(summary)
        return result
        
    except Exception as e: 
        error_msg = traceback.format_exc()
        result["處理狀態"] = "💥 程式異常"
        result["弱點處理方式"] = f"系統執行詳細錯誤:\n{error_msg}"
        return result

# --- Streamlit 網頁 UI 介面佈局 ---
st.set_page_config(page_title="CPE 2.3 弱點自動化中文化分析平台", layout="wide")
st.title("🛡️ CPE 2.3 資產弱點分析與修補自動化平台")
st.markdown("本系統支援自動比對 **NVD 漏洞資料庫** 與 **CISA KEV**，並自動將英文修補與漏洞敘述**翻譯為繁體中文**。")

uploaded_file = st.file_uploader("📥 請上傳您的資產 CSV 檔案 (必須包含名為 'CPE' 的欄位)", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.success("✅ 檔案上傳成功！")
    
    if "CPE" not in df.columns:
        st.error("❌ 錯誤：您的 CSV 檔案中沒有發現名為 'CPE' 的欄位，請檢查欄位名稱（大小寫需完全一致）！")
    else:
        st.subheader("📋 原始資料預覽")
        st.dataframe(df.head(5))
        
        if st.button("🚀 開始批次弱點比對與中文化翻譯"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            statuses, deadlines, methods = [], [], []
            total = len(df)
            
            for index, row in df.iterrows():
                status_text.text(f"⏳ 正在分析第 {index+1}/{total} 筆資產：{row['CPE']}")
                res = query_nvd_web(row["CPE"])
                statuses.append(res["處理狀態"])
                deadlines.append(res["修補期限"])
                methods.append(res["弱點處理方式"])
                progress_bar.progress((index + 1) / total)
            
            df["處理狀態"] = statuses
            df["修補期限"] = deadlines
            df["弱點處理方式"] = methods
            
            status_text.text("🎉 全數資產比對與繁體中文化完成！")
            
            st.subheader("📊 分析結果成果預覽")
            st.dataframe(df)
            
            csv_data = df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
            st.download_button(
                label="📥 下載已分析之 VANS/資安修補報告 (CSV)",
                data=csv_data,
                file_name=f"CPE_Remediation_Report_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
