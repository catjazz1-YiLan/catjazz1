import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import requests
import time
import urllib.parse

def translate_to_tw(text):
    """
    使用 Google 官方 Web API 將漏洞英文敘述翻譯成繁體中文
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

def query_osv_api(cpe_string):
    """
    全新核心邏輯：串接 Google OSV API 進行 CPE 2.3 弱點查詢，免 Key 且 100% 繞過 NVD 封鎖
    """
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "查無已知弱點，資產安全。"}
    if pd.isna(cpe_string) or not str(cpe_string).strip(): 
        return result
    
    clean_cpe = cpe_string.strip()
    
    try:
        # OSV API 查詢終端點
        url = "https://osv.dev"
        
        # OSV 標準的 CPE 2.3 查詢 JSON 結構
        payload = {
            "version": "1.0.0",
            "query": {
                "cpe": clean_cpe
            }
        }
        
        # 發送 POST 請求 (OSV 規定使用 POST)
        response = requests.post(url, json=payload, timeout=10)
        
        # 💡 OSV 沒有嚴格的限流，只需要稍微冷卻 0.2 秒維持網頁流暢度即可
        time.sleep(0.2)
        
        if response.status_code != 200:
            result["處理狀態"] = f"⚠️ 資料庫忙碌 ({response.status_code})"
            result["弱點處理方式"] = "OSV 資料庫目前回應不正常，請稍候重試。"
            return result
            
        # OSV 若找到弱點，會回傳一個名為 'vulns' 的陣列
        vulns_data = response.json().get("vulns", [])
        if not vulns_data:
            return result # 查無弱點，回傳預設的「免辦理」
            
        summary = []
        has_critical = False
        
        # 提取前 3 個最主要的弱點分析
        for idx, v in enumerate(vulns_data[:3], 1):
            vuln_id = v.get("id", "未知編號") # 通常是 GHSA 或 CVE 編號
            details_en = v.get("details", "No description provided.")
            
            # 將說明翻譯成繁體中文
            details_zh = translate_to_tw(details_en)
            
            # 撈取官方修補與資安公告超連結
            references = v.get("references", [])
            links = [ref.get("url") for ref in references if ref.get("url")]
            links_str = " | ".join(links[:2]) if links else "請參閱 OSV 官方網頁公告"
            
            # 簡單判定是否為緊急漏洞 (OSV 會在 ID 中標註或是具體說明中包含關鍵字)
            is_critical = "critical" in details_en.lower() or "rce" in details_en.lower()
            if is_critical:
                has_critical = True
                
            critical_tag = " [⚠️ 判定為高風險/嚴重弱點!]" if is_critical else ""
            summary.append(f"【{idx}】{vuln_id}{critical_tag}\n🔹漏洞說明: {details_zh}\n🔗公告與修補連結: {links_str}")
            
        # 分類處理優先級
        if has_critical:
            result["處理狀態"] = "🚨 14天內強制修補"
            result["修補期限"] = (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
        else:
            result["處理狀態"] = "⏳ 需進行修補"
            result["修補期限"] = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            
        result["弱點處理方式"] = "\n\n".join(summary)
        return result
        
    except Exception as e:
        result["處理狀態"] = "💥 處理異常"
        result["弱點處理方式"] = f"查詢發生未知錯誤: {str(e)}"
        return result

# --- Streamlit 網頁 UI 介面佈局 ---
st.set_page_config(page_title="CPE 2.3 弱點自動化中文化分析平台 (OSV 核心)", layout="wide")
st.title("🛡️ CPE 2.3 資產弱點分析與修補自動化平台 (Google OSV 備援版)")
st.markdown("因應 NVD 官方限制雲端 IP，本系統已自動無縫切換至 **Google OSV 全球漏洞資料庫**。**免輸入 API Key**，直接支援 CPE 2.3 繁體中文化比對。")

uploaded_file = st.file_uploader("📥 請上傳您的資產 CSV 檔案 (必須包含名為 'CPE' 的欄位)", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.success("✅ 檔案上傳成功！")
    
    if "CPE" not in df.columns:
        st.error("❌ 錯誤：您的 CSV 檔案中沒有發現名為 'CPE' 的欄位！")
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
                # 呼叫全新的免 Key OSV 函數
                res = query_osv_api(row["CPE"])
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
                file_name=f"CPE_OSV_Remediation_Report.csv",
                mime="text/csv"
            )
