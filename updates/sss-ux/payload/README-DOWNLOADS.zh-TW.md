# SSS 安裝版本

建議下載 **SSS-0.4.5-UX-Auto-Setup-r3.exe**。精靈會讀取實際 Windows 版本、原生架構、.NET 版本及安裝環境，顯示選定的相容版本；確認後才開啟該版本的安裝精靈。完整包可離線選版，不必再次下載程式檔。

| 入口 | 適用系統 | 安裝包 | ZIP 備援 |
| --- | --- | --- | --- |
| 自動偵測（建議） | 下列兩種 64 位元系統 | [自動偵測 EXE](SSS-0.4.5-UX-Auto-Setup-r3.exe) | [完整 ZIP](SSS-0.4.5-UX-Auto-Setup-r3.zip) |
| Windows 7 | Windows 7 SP1、64 位元 | [Win7 EXE](SSS-0.4.5-UX-Win7-Setup-r2.exe) | [Win7 ZIP](SSS-0.4.5-UX-Win7-Setup-r2.zip) |
| Windows 10／11 | 64 位元、組建 19041 以上 | [Win10／11 EXE](SSS-0.4.5-UX-Win10-11-Setup-r2.exe) | [Win10／11 ZIP](SSS-0.4.5-UX-Win10-11-Setup-r2.zip) |

所有版本都需要 .NET Framework 4.8 或以上。32 位元、ARM、Windows Server 與 Windows 8／8.1 不在此包支援範圍。未符合條件時精靈會顯示原因並停止。

從普通 Windows 檔案總管開啟安裝包。若使用 ZIP，先完整解壓縮，再開啟 `Setup.vbs`。安裝保留既有程式與資料；自動選版會核對子安裝器及設定檔的大小與 SHA256。摘要見 [sha256.txt](sha256.txt)，版本清單見 [download-catalog.json](download-catalog.json)。

這是 **SSS 0.4.5 UX 開發候選版**。Windows 11 本機的獨立目錄安裝、捷徑、啟動及自動選版偵測已有實測；Windows 7 POS 實機驗收尚未完成。原生防火牆、掃毒、清理與正式 Ready 尚未啟用。SSS 協助 SSL 更新後重啟及重連的功能另在開發，未包含於此版。

安裝精靈不會建立開機自啟或自動分享。開啟 SSS 後會顯示實際 Windows 狀態並記錄程式活動；背景程序執行與原生防護啟用是不同狀態。
