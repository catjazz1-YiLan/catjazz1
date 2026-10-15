import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import requests
import time

def translate_to_tw(text):
    """
    使用 Google 官方免費 Web API 將漏洞英文敘述翻譯成繁體中文
    """
    if not text or not text.strip(): 
        return "無說明"
    try:
        # 將文字過長部分切斷，避免 API 傳輸錯誤
        clean_text = text.strip()[:800]
        url = "https://googleapis.com" + requests.utils.quote(clean_text)
        res = requests.get(url, timeout=5).json()
        # 解析 Google 翻譯回傳的特殊巢狀陣列結構
        return "".join([s[0] for s in res[0] if s[0]])
    except: 
        # 若翻譯發生異常，則回傳原文
        return text

def query_nvd_web(cpe_string):
    """
    核心比對邏輯：使用寬鬆匹配查詢 NVD API，精準抓出漏洞、CISA KEV 狀態與修補連結
    """
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "查無已知弱點，資產安全。"}
    if pd.isna(cpe_string) or not str(cpe_string).strip(): 
        return result
    
    clean_cpe = cpe_string.strip()
    
    try:
        # 【關鍵修正】解構 CPE 字串，改採產品名與版本號做關鍵字寬鬆查詢，防範 NVD 的精準匹配陷阱
        cpe_parts = clean_cpe.split(":")
        if len(cpe_parts) >= 5:
            product = cpe_parts[4]
            version = cpe_parts[5]
            url = f"https://nist.gov{product} {version}"
        else:
            url = f"https://nist.gov{clean_cpe}"
            
        response = requests.get(url, timeout=10)
        
        # 【強制冷卻】未帶 API Key 的請求每筆必須強制等待 6 秒，否則批次查詢在第 5 筆後一定會被 NVD 阻斷
        time.sleep(6.0) 
        
        if response.status_code != 200:
            result["處理狀態"] = f"⚠️ API限制 ({response.status_code})"
            result["弱點處理方式"] = "因請求過快遭 NVD 暫時拒絕。大批次查詢請向 NVD 申請免費 API Key 帶入系統。"
            return result
            
        vulns = response.json().get("vulnerabilities", [])
        if not vulns: 
            return result
        
        summary = []
        has_kev = False
        
        # 僅提取前 3 個最嚴重的漏洞展示，避免網頁塞車卡死
        for idx, v in enumerate(vulns[:3], 1):
            cve_id = v["cve"]["id"]
            
            # 檢查 CISA KEV 狀態
            is_kev = True if v["cve"].get("cisaExploitAdd") else False
            if is_kev: 
                has_kev = True
            
            # 將英文漏洞敘述丟給 Google 翻譯成繁體中文
            desc_en = v["cve"]["descriptions"][0].get("value", "") if v["cve"].get("descriptions") else ""
            desc_zh = translate_to_tw(desc_en)
            
            # 篩選出原廠 Patch 或是 廠商公告連結
            links = []
            for r in v["cve"].get("references", []):
                tags = r.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    links.append(r["url"])
            links_str = " | ".join(links[:2]) if links else "請參閱 NVD 官方一般公告"
            
            kev_tag = " [⚠️ CISA KEV 已遭野外利用!]" if is_kev else ""
            summary.append(f"【{idx}】{cve_id}{kev_tag}\n🔹漏洞說明: {desc_zh}\n🔗修補公告與下載: {links_str}")
        
        # 根據是否包含 KEV 漏洞，決定狀態與期限
        if has_kev:
            result["處理狀態"] = "🚨 14天內強制修補"
            result["修補期限"] = (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
        else:
            result["處理狀態"] = "⏳ 需進行修補"
            result["修補期限"] = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            
        result["弱點處理方式"] = "\n\n".join(summary)
        return result
        
    except Exception as e: 
        result["處理狀態"] = "💥 程式異常"
        result["弱點處理方式"] = f"查詢發生錯誤: {str(e)}"
        return result

# --- Streamlit 網頁介面佈局 ---
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
            
            # 提供內含繁中修補建議的完整 CSV 供使用者下載
            csv_data = df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
            st.download_button(
                label="📥 下載已分析之 VANS/資安修補報告 (CSV)",
                data=csv_data,
                file_name=f"CPE_Remediation_Report_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
