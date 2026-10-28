Solar System Link POS 0.6.0-r1 安裝版（開發測試版）

本安裝包是 POS 被控端，適用 Windows 7 SP1 x64 或較新 x64 Windows，需要 .NET Framework 4.8。
雙擊 SolarSystemLink-POS-Setup-0.6.0-r1.exe 即可安裝到目前 Windows 使用者，建立「Solar System Link POS 0.6.0」桌面與開始功能表捷徑。請用平常操作 POS 的相同 Windows 帳戶安裝。
缺少 .NET 4.8 時會先停止並顯示提示；官方下載：https://dotnet.microsoft.com/en-us/download/dotnet-framework/thank-you/net48-offline-installer
本包不下載元件、不要求管理員、不更改防火牆或系統安全設定。

原本有舊版
1. 在舊 POS 被控程式按停止分享，關閉程式視窗；若仍有主控連線，先正常中斷。
2. 雙擊新版安裝檔。新版採獨立程式目錄，不卸載、覆寫舊版或刪除舊捷徑。
3. 安裝完成後，從桌面「Solar System Link POS 0.6.0」開啟新版，不要同時開新舊被控程式。
4. 新舊版使用相同帳戶的既有 DirectDevice-v1 資料。安裝器不讀取、複製或重設固定六碼、裝置身分、主控綁定與安全嘗試紀錄。
5. 若原資料損壞或帳戶不同，程式可能拒絕載入；請保留資料尋求修復，不要刪除資料或按重設固定碼。

連線
1. 開啟被控程式，按「開始分享」。安裝不會自動啟動程式或分享，也不會啟用開機常駐。
2. 主控使用 POS 的 IP、既有信任及固定六碼連線。若需要「儲存連線設定」，JSON 只傳公開設定，不傳六碼或秘密資料。
3. 這一版每次連線仍須 POS 本機勾選「允許滑鼠與鍵盤控制」，主控再開操作模式。
4. 先用空白記事本測試；不要以收銀、結帳或付款作測試。

解除安裝：Windows 程式清單選「Solar System Link POS 0.6.0」。只移除本版已核對的程式與捷徑；保留舊版、固定碼與身分、其他使用者檔案。被修改的檔案會保留並停止，不強制刪除。
失敗／中斷：關閉自己的安裝視窗和被控程式，再用同版原安裝檔重試。不要手動刪除 .lock、交易紀錄、憑證或 DPAPI 資料。錯誤 4 表示未知或被修改的狀態，錯誤 5 表示被控程式仍開啟或無法取得排他存取。

實機限制
本包不是完整 SSS 防火牆，不包含無人值守授權，也不改變現有操作允許規則。0.6.7 是主控／更新版本；本包的獨立 Agent 真實版本是 0.6.0。
本輪完成本機隔離安裝測試，不代表這台 Windows 7 POS 已安裝或已通過鍵鼠與持續操作驗收。
需要可互通的區網或既有 VPN，使用 TCP 45731；沒有網際網路中繼。鎖屏、UAC 安全桌面與較高權限程式不支援遠端操作。
由普通 Windows 檔案總管下載並執行；在 Codex 套件環境測試的路徑不能當作普通安裝證據。
本包無新增付費或付費點數。使用公開領域 LZMA SDK 26.05 SFX：https://www.7-zip.org/sdk.html

安裝版：0.6.0 r1。採獨立程式目錄，保留舊版；固定六碼、裝置身分與使用者額外檔案不由安裝器讀取或更改。
本次修正版尚未在 Windows 7／實際 POS 驗收；本機隔離測試不代表實機連線成功。

This installer uses the public-domain LZMA SDK 26.05 SFX module. Source and license: https://www.7-zip.org/sdk.html
