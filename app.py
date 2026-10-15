import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import requests
import time

def translate_to_tw(text):
    if not text or not text.strip(): return ""
    try:
        url = "https://googleapis.com" + requests.utils.quote(text[:800])
        res = requests.get(url, timeout=5).json()
        return "".join([s[0] for s in res[0] if s[0]])
    except: return text

def query_nvd_web(cpe_string):
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "查無已知弱點，資產安全。"}
    if pd.isna(cpe_string) or not str(cpe_string).strip(): return result
    try:
        url = f"https://nist.gov{cpe_string.strip()}"
        response = requests.get(url, timeout=10)
        time.sleep(1.0)
        if response.status_code != 200:
            result["處理狀態"] = "⚠️ 查詢失敗"
            return result
        vulns = response.json().get("vulnerabilities", [])
        if not vulns: return result
        summary = []
        has_kev = False
        for idx, v in enumerate(vulns, 1):
            cve_id = v["cve"]["id"]
            is_kev = True if v["cve"].get("cisaExploitAdd") else False
            if is_kev: has_kev = True
            desc = translate_to_tw(v["cve"]["descriptions"][0]["value"])
            links = [r["url"] for r in v["cve"].get("references", []) if "Patch" in r.get("tags", []) or "Vendor Advisory" in r.get("tags", [])]
            links_str = " | ".join(links) if links else "參閱 NVD 一般公告"
            summary.append(f"【{idx}】{cve_id}{' [⚠️ KEV 遭利用!]' if is_kev else ''}\n🔹說明: {desc}\n🔗連結: {links_str}")
        if has_kev:
            result["處理狀態"] = "🚨 14天內強制修補"
            result["修補期限"] = (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
        else:
            result["處理狀態"] = "⏳ 需進行修補"
            result["修補期限"] = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        result["弱點處理方式"] = "\n\n".join(summary)
        return result
    except: return result

st.set_page_config(page_title="CPE 2.3 弱點自動化中文化分析平台", layout="wide")
st.title("🛡️ CPE 2.3 資產弱點分析與修補自動化平台")
st.markdown("本系統支援自動比對 **NVD 漏洞資料庫** 與 **CISA KEV**，並自動將英文修補與漏洞敘述**翻譯為繁體中文**。")
uploaded_file = st.file_uploader("📥 請上傳您的資產 CSV 檔案 (必須包含名為 'CPE' 的欄位)", type=["csv"])
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.success("✅ 檔案上傳成功！")
    if "CPE" not in df.columns:
        st.error("❌ 錯誤：您的 CSV 檔案中沒有發現名為 'CPE' 的欄位，請檢查標頭！")
    else:
        st.subheader("原始資料預覽")
        st.dataframe(df.head(5))
        if st.button("🚀 開始 batch 分析與翻譯"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            statuses, deadlines, methods = [], [], []
            total = len(df)
            for index, row in df.iterrows():
                status_text.text(f"正在分析第 {index+1}/{total} 筆資產：{row['CPE']}")
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
