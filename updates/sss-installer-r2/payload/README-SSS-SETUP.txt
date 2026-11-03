SSS 單檔安裝器 0.5.0-r2（開發測試版）

下載 SSS-Setup-050-r2.exe 後於符合條件的 Windows 電腦雙擊。
新的 wrapper 身分為 SolarSystemShield.SingleFileInstaller.Candidate.R2，Assembly／FileVersion 1.0.1.0。SSS 執行版本仍為原 0.5.0.0／sequence 7；原簽署目錄、bootstrap、ZIP 和公開 r1 不變。

來源層條件：Windows 7 SP1 x64，或 Windows 10／11 x64（build 19041 以上），一般使用者權限且可取得有效官方版本；必須已安裝 .NET Framework 4.8。未內附 CLR／.NET 安裝程式，缺少 CLR4 無法進入 managed 精靈；未提供 x86、ARM64、macOS、iOS 安裝包。

r2 只新增一條原合法更新路徑：既有 0.4.8.0 的精確原發行套件（SHA256 8bb2dda57da5a8eceb95853939c13cab65d0d9385ec92d42ebb5368962524764），且原更新器實際檔案經核對為 ReviewedR7。原有 >=0.4.9.0 路徑保留。0.4.6／075A、0.4.7／R6、未知組合、更新器回覆 11 的正常退出／移轉缺口仍未解決；不覆寫或重建身分，不強制結束程式。版本下限、高水位、工作原期限與真正背景啟動確認仍需通過。

原驗證歷史如實保留，四個程序退出碼依序 0/1/0/0：wrapper 編譯成功；第一次資料主機因缺 Get-FileHash、尚未完成第一案例而失敗；獨立覆核後的資料主機成功完成三項原消費者選路檢查；原先未執行的 metadata 檢查成功。沒有重編或重跑 r1 原 12 項。40 項新 UTF8 資料、15 項既存 runtime 雜湊及 3 項 fixture metadata 為不同證據層，不宣稱 57 項全部新鮮重驗。

限制：
- 未作 Authenticode 簽署；檔案 SHA256 用於交付核對，不是新信任根。內嵌材料仍由原簽署目錄與原更新器驗證。
- 普通 Windows 安裝、真正的 0.4.8 升級、Windows 7／POS、SSL 更新重啟重連、鍵鼠／IME 持續操作及完整原生防護尚未完成驗收。
- prerelease 開發測試版不代表穩定正式版或所有 OS 可用。
- 僅指定 R2 EXE 是交付物；R6／R7／Unknown 資料程式不是安裝包，不隨本發行上傳。

EXE：1016320 bytes；SHA256 69866a812834a6ca4d1b113ac54077359ccbe7dfd9538dc6f9064a2f142555a4。
另附 SSS-Setup-050-r2.manifest.json 與 SHA256SUMS.txt，可核對版本、限制及檔案摘要。
