import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import requests
import time
import urllib.parse
import traceback

def translate_to_tw(text):
    if not text or not text.strip(): return "無說明"
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
    except: return text

def clean_cpe_for_nvd(cpe_string):
    if not cpe_string: return ""
    parts = cpe_string.strip().split(":")
    if len(parts) >= 6: return ":".join(parts[:6])
    return cpe_string.strip()

def query_nvd_web(cpe_string, api_key):
    """
    修改此處：加入 api_key 參數來繞過 Cloudflare 防火牆
    """
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "查無已知弱點，資產安全。"}
    if pd.isna(cpe_string) or not str(cpe_string).strip(): return result
    
    target_cpe = clean_cpe_for_nvd(cpe_string)
    
    # 建立授權 Header
    headers = {}
    if api_key and api_key.strip():
        headers["apiKey"] = api_key.strip()
    
    try:
        base_url = "https://nist.gov"
        query_params = {"cpeName": target_cpe}
            
        # 攜帶 Key 發送請求
        response = requests.get(base_url, params=query_params, headers=headers, timeout=12)
        
        # 💡 有帶 Key 的情況下，冷卻時間可以從 6.5 秒大幅縮短到 0.6 秒！
        time.sleep(0.6) 
        
        if response.status_code != 200:
            parts = target_cpe.split(":")
            if len(parts) >= 5:
                backup_keyword = f"{parts} {parts}" if len(parts) >= 6 else parts
                response = requests.get(base_url, params={"keywordSearch": backup_keyword}, headers=headers, timeout=12)
                time.sleep(0.6)
                
            if response.status_code != 200:
                result["處理狀態"] = f"⚠️ API限制 ({response.status_code})"
                result["弱點處理方式"] = f"伺服器拒絕，請確認 API Key 是否填寫正確。"
                return result
        
        if "application/json" not in response.headers.get("Content-Type", "").lower():
            result["處理狀態"] = "⚠️ 回應格式異常"
            result["弱點處理方式"] = "依然撞到 Cloudflare 防火牆，請確認網頁左側是否有正確輸入免費申請的 NVD API Key。"
            return result
            
        vulns = response.json().get("vulnerabilities", [])
        if not vulns: return result
        
        summary = []
        has_kev = False
        
        for idx, v in enumerate(vulns[:3], 1):
            cve_id = v["cve"]["id"]
            is_kev = True if v["cve"].get("cisaExploitAdd") else False
            if is_kev: has_kev = True
            
            desc_list = v["cve"].get("descriptions", [])
            desc_en = ""
            for d in desc_list:
                if d.get("lang") == "en":
                    desc_en = d.get("value", "")
                    break
            
            desc_zh = translate_to_tw(desc_en)
            
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
        result["處理狀態"] = "💥 程式異常"
        result["弱點處理方式"] = f"錯誤:\n{traceback.format_exc()}"
        return result

# --- UI 佈局 ---
st.set_page_config(page_title="CPE 2.3 弱點自動化中文化分析平台", layout="wide")
st.title("🛡️ CPE 2.3 資產弱點分析與修補自動化平台")

# 💡 在網頁左側側邊欄新增一個輸入框，讓使用者可以直接貼上 API Key 測試，安全又彈性
with st.sidebar:
    st.subheader("🔑 認證設定")
    nvd_key = st.text_input("請輸入 NVD API Key (建議填寫以繞過限流)", type="password")
    st.markdown("[👉 免費申請 NVD API Key](https://nist.gov)")

uploaded_file = st.file_uploader("📥 請上傳您的資產 CSV 檔案 (必須包含名為 'CPE' 的欄位)", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.success("✅ 檔案上傳成功！")
    
    if "CPE" not in df.columns:
        st.error("❌ 錯誤：CSV 檔案中沒有發現 'CPE' 欄位！")
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
                # 傳遞 api_key 進去
                res = query_nvd_web(row["CPE"], nvd_key)
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
                file_name=f"CPE_Remediation_Report.csv",
                mime="text/csv"
            )
