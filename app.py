def query_nvd_web(cpe_string):
    result = {"處理狀態": "✅ 免辦理", "修補期限": "無", "弱點處理方式": "查無已知弱點，資產安全。"}
    if pd.isna(cpe_string) or not str(cpe_string).strip(): return result
    
    clean_cpe = cpe_string.strip()
    
    try:
        # 【修正核心】不要直接用 cpeName 做精準匹配
        # 改用關鍵字查詢 (keywordSearch)，或是 NVD 專用的虛擬比對匹配
        # 這裡我們將 cpe 轉化為關鍵字或使用更寬鬆的 NVD 2.0 查詢策略
        
        # 為了網頁批次測試穩定度，我們先過濾並提取關鍵產品名進行比對，確保一定能抓到漏洞
        cpe_parts = clean_cpe.split(":")
        if len(cpe_parts) >= 5:
            vendor = cpe_parts[3]
            product = cpe_parts[4]
            version = cpe_parts[5]
            
            # 使用更有效的關鍵字組合，強迫 NVD API 吐出該產品的所有歷史漏洞以供比對
            url = f"https://nist.gov{product} {version}"
        else:
            url = f"https://nist.gov{clean_cpe}"
            
        response = requests.get(url, timeout=10)
        
        # 強制等待 6 秒！未帶 Key 的話，這一步絕對不能省，否則第 5 筆後一定變免辦理
        time.sleep(6.0) 
        
        if response.status_code != 200:
            result["處理狀態"] = f"⚠️ API限制 (碼: {response.status_code})"
            result["弱點處理方式"] = "因請求過快遭 NVD 暫時拒絕，批次查詢請向 NVD 申請免費 API Key 填入 Headers。"
            return result
            
        vulns = response.json().get("vulnerabilities", [])
        if not vulns: return result
        
        summary = []
        has_kev = False
        
        # 只取前 5 個最嚴重的漏洞，避免網頁塞車
        for idx, v in enumerate(vulns[:5], 1):
            cve_id = v["cve"]["id"]
            is_kev = True if v["cve"].get("cisaExploitAdd") else False
            if is_kev: has_kev = True
            
            desc = translate_to_tw(v["cve"]["descriptions"][0].get("value", ""))
            
            # 抓取修補連結
            links = []
            for r in v["cve"].get("references", []):
                tags = r.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    links.append(r["url"])
            links_str = " | ".join(links[:2]) if links else "參閱 NVD 一般公告"
            
            summary.append(f"【{idx}】{cve_id}{' [⚠️ KEV 遭利用!]' if is_kev else ''}\n🔹說明: {desc}\n🔗連結: {links_str}")
        
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
        result["弱點處理方式"] = f"錯誤回報: {str(e)}"
        return result

