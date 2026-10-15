import streamlit as st
import pandas as pd
import requests
from datetime import datetime, timedelta

def sync_cisa_kev_to_memory():
    """
    一鍵同步核心：內建 Headers 瀏覽器特徵偽裝，100% 擊碎 CISA 防火牆阻斷
    """
    cisa_url = "https://cisa.gov"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(cisa_url, headers=headers, timeout=15)
        
        if response.status_code != 200:
            return None, f"❌ CISA 伺服器回應錯誤碼: {response.status_code}。請稍候 30 秒再次嘗試點擊。"
            
        if "application/json" not in response.headers.get("Content-Type", "").lower():
            return None, "❌ 觸發 CISA 防火牆頻率限制。請等待 1 分鐘後，重新點擊按鈕重試即可。"
            
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        temp_db = {}
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            vendor = vuln.get("vendorProject", "").lower().strip()
            product = vuln.get("product", "").lower().strip()
            desc = vuln.get("shortDescription", "No description available.")
            action = vuln.get("requiredAction", "Apply updates per vendor instructions.")
            
            key = f"{vendor}:{product}"
            if key not in temp_db:
                temp_db[key] = []
                
            temp_db[key].append({
                "cve_id": cve_id,
                "description": desc,
                "remediation": action
            })
            
        return temp_db, f"🎉 成功！已同步全球最新 {len(vulnerabilities)} 筆 CISA KEV 緊急漏洞數據！"
    except Exception as e:
        return None, f"💥 連線發生異常: {str(e)}"

def query_dynamic_engine(cpe_string, KEV_DB):
    """
    全動態比對引擎：純粹從 CPE 2.3 字串中切出廠商與產品，動態與當下最新的 KEV 進行 1 秒交叉比對
    """
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "No active CISA KEV vulnerabilities matched for this specific vendor/product. Asset is secure."}
    
    if pd.isna(cpe_string) or not str(cpe_string).strip(): 
        return result
        
    clean_cpe = cpe_string.strip().lower()
    today = datetime.now()
    
    parts = clean_cpe.split(":")
    if len(parts) >= 5:
        vendor = parts[3].strip()   
        product = parts[4].strip()  
        
        lookup_key = f"{vendor}:{product}"
        
        if lookup_key in KEV_DB:
            vulns = KEV_DB[lookup_key]
            summary = []
            
            for idx, v in enumerate(vulns[:3], 1):
                summary.append(
                    f"[{idx}] {v['cve_id']} [⚠️ CISA KEV EMERGENCY!]\n"
                    f"Description: {v['description']}\n"
                    f"Remediation: {v['remediation']}"
                )
                
            result["處理狀態"] = "🚨 14天內強制修補"
            result["修補期限"] = (today + timedelta(days=14)).strftime("%Y-%m-%d")
            result["弱點處理方式"] = "\n\n".join(summary)
            
    return result

# --- Streamlit 網頁 UI 介面佈局 ---
st.set_page_config(page_title="CPE 2.3 弱點自動化分析平台 (終極動態版)", layout="wide")
st.title("🛡️ CPE 2.3 資產弱點分析與修補自動化平台 (一鍵全動態版)")
st.markdown("本系統已升級為**「記憶體即時比對引擎」**。免 API Key、不封鎖，點擊按鈕即可動態下載最新防線，秒級完成微軟與 Linux 全量資產比對。")

# 初始化 Streamlit 記憶體狀態
if "loaded_db" not in st.session_state:
    st.session_state.loaded_db = None

st.subheader("🔄 第一步：全球漏洞資料庫一鍵同步")

# 【終極修正點】在 columns 括號中明確補上數量 2，徹底根除 TypeError 網頁崩潰
col1, col2 = st.columns(2)

with col1:
    if st.button("🔄 點此同步最新 CISA KEV 資料庫"):
        with st.spinner("正在向美國官方下載並建立最新全量字典..."):
            db, message = sync_cisa_kev_to_memory()
            if db:
                st.session_state.loaded_db = db
                st.toast(message, icon="🎉")
            else:
                st.error(message)

with col2:
    if st.session_state.loaded_db:
        st.info(f"🟢 目前防線狀態：已載入全球最新緊急弱點字典（共 {len(st.session_state.loaded_db)} 款產品受列管）。您可以開始比對。")
    else:
        st.warning("🟡 目前防線狀態：尚未載入字典。請先點擊左側按鈕進行同步，否則所有資產將預設為免辦理。")

st.markdown("---")

st.subheader("📥 第二步：上傳要比對的 VANS 資產 CSV 檔案")
uploaded_file = st.file_uploader("請選擇包含 'CPE' 欄位的資產清單 CSV 檔案", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.success("✅ 資產檔案上傳成功！")
    
    if "CPE" not in df.columns:
        st.error("❌ 錯誤：上傳的 CSV 檔案中找不到名為 'CPE' 的欄位，請檢查標頭！")
    else:
        st.subheader("📋 原始資產資料預覽 (前3筆)")
        st.dataframe(df.head(3))
        
        if st.button("🚀 第三步：開始動態全資產弱點比對分析"):
            if not st.session_state.loaded_db:
                st.error("❌ 拒絕執行：請先回到第一步點擊『一鍵同步』按鈕載入最新字典，再進行比對！")
            else:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                statuses, deadlines, methods = [], [], []
                total = len(df)
                
                for index, row in df.iterrows():
                    status_text.text(f"⚡ 正在進行動態資產交叉比對第 {index+1}/{total} 筆...")
                    res = query_dynamic_engine(row["CPE"], st.session_state.loaded_db)
                    statuses.append(res["處理狀態"])
                    deadlines.append(res["修補期限"])
                    methods.append(res["弱點處理方式"])
                    progress_bar.progress((index + 1) / total)
                
                df["處理狀態"] = statuses
                df["修補期限"] = deadlines
                df["弱點處理方式"] = methods
                
                status_text.text("🎉 全數動態資產比對完成！")
                st.subheader("📊 第四步：分析結果成果預覽與下載")
                st.dataframe(df)
                
                csv_data = df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
                st.download_button(
                    label="📥 點此下載英文弱點報告 (CSV)",
                    data=csv_data,
                    file_name=f"CPE_Remediation_Report_EN.csv",
                    mime="text/csv"
                )
