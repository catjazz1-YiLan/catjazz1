import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import requests
import time
import urllib.parse
import traceback  # 引入錯誤追蹤工具

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
        
        # 修正：最安全的巢狀陣列解析法，避免強轉 str 造成崩潰
        translated_segments = []
        if res and isinstance(res, list) and len(res) > 0 and res[0]:
            for item in res[0]:
                if item and isinstance(item, list) and len(item) > 0 and item[0]:
                    translated_segments.append(item[0])
        return "".join(translated_segments) if translated_segments else text
    except Exception as te: 
        # 翻譯如果壞掉，至少保留英文原文，不要讓整支程式崩潰
        return f"[翻譯異常，保留原文] {text} (錯誤原因: {str(te)})"

def query_nvd_web(cpe_string):
    """
    核心比對邏輯：使用標準官方匹配策略進行查詢，並在發生錯誤時直接回傳報錯訊息
    """
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "查無已知弱點，資產安全。"}
    if pd.isna(cpe_string) or not str(cpe_string).strip(): 
        return result
    
    clean_cpe = cpe_string.strip()
    
    try:
        # 將整個 CPE 2.3 字串進行標準的 URL 安全編碼
        encoded_cpe = urllib.parse.quote(clean_cpe)
        
        # 採用 NVD 官方最穩定、最標準的 cpeName 查詢 Endpoint
        url = f"https://nist.gov{encoded_cpe}"
            
        response = requests.get(url, timeout=10)
        
        # 【重要機制】未帶 API Key 每筆查詢後強制冷卻 6.5 秒，這能 100% 確保批次掃描不被官方封鎖
        time.sleep(6.5) 
        
        # 如果因為請求過快遇到限制 (例如 403 或 429)，將狀態如實反映
        if response.status_code != 200:
            result["處理狀態"] = f"⚠️ API限制 ({response.status_code})"
            result["弱點處理方式"] = f"因批次請求過快遭 NVD 資料庫限制，請稍候重試。網址: {url}"
            return result
            
        vulns = response.json().get("vulnerabilities", [])
        if not vulns: 
            return result
        
        summary = []
        has_kev = False
        
        # 僅提取前 3 個最主要的漏洞展示，確保效能與排版整齊
        for idx, v in enumerate(vulns[:3], 1):
            cve_id = v["cve"]["id"]
            
            # 檢查 CISA KEV 狀態
            is_kev = True if v["cve"].get("cisaExploitAdd") else False
            if is_kev: 
                has_kev = True
            
            # 安全地撈取英文漏洞說明
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
        
        # 根據是否包含 KEV 漏洞，自動判定優先級與期限
        if has_kev:
            result["處理狀態"] = "🚨 14天內強制修補"
            result["修補期限"] = (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
        else:
            result["處理狀態"] = "⏳ 需進行修補"
            result["修補期限"] = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            
        result["弱點處理方式"] = "\n\n".join(summary)
        return result
        
    except Exception as e: 
        # 【核心 Debug 升級】不再只寫程式異常，直接吐出 Python 的錯誤切確行數與原因
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
