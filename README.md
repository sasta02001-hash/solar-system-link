# Solar System Link

Solar System Link（SSL）與 Solar System Shield（SSS）的 Windows 安裝檔及官方簽章更新來源。

| 產品 | 公開版本 | 下載 |
| --- | --- | --- |
| SSL Windows／POS | 0.7.0-r1 | [安裝 EXE](https://github.com/sasta02001-hash/solar-system-link/releases/download/ssl-windows-v0.7.0-r1/SolarSystemLink-Windows-x64-Setup-0.7.0-r1.exe) · [ZIP](https://github.com/sasta02001-hash/solar-system-link/releases/download/ssl-windows-v0.7.0-r1/SolarSystemLink-Windows-x64-Setup-0.7.0-r1.zip) · [說明與摘要](https://github.com/sasta02001-hash/solar-system-link/releases/tag/ssl-windows-v0.7.0-r1) |
| SSL 既有可信安裝線上更新 | 0.7.0.0，序號 5 | [簽章執行期](https://github.com/sasta02001-hash/solar-system-link/releases/tag/ssl-v0.7.0.0)，透過原 Launcher／Updater 更新。 |
| SSS 背景介面與更新候選 | 0.4.6.0，序號 1 | [初始安裝 ZIP](https://github.com/sasta02001-hash/solar-system-link/releases/download/sss-ui-v0.4.6.0/SSS-0.4.6.0-Background-Initial-Setup.zip) · [版本資料](https://github.com/sasta02001-hash/solar-system-link/releases/tag/sss-ui-v0.4.6.0)。解壓後執行 Install-SSS-Background.vbs。 |

適用 Windows 7 SP1／Windows 10、11 x64，需 .NET Framework 4.8；安裝器會核對環境。尚未提供 x86 或 ARM64 安裝包。

SSL 0.7.0 在開始連線時先自動準備本地 SSS 更新及背景檢查，通過後才連線；認證後亦檢查對端。鍵鼠仍須原有效裝置信任與操作授權。兩產品各用固定公鑰驗證自己的更新，不以 SSS 背景狀態取代操作授權。新版包含更新後重開與有限重連。

目前十四個公開下載檔均已匿名重新下載並核對長度與 SHA-256。普通 Windows SSL 已從 0.6.7 線上更新並啟動 0.7.0。實際按連線已先觸發本地 SSS；目前 SSS 官方目錄的 .NET 網路檢查仍待修復，未通過時不建立裝置連線。公開發行及來源測試不代表 POS 實機鍵鼠、持續操作、完整無人值守或 SSS 原生防護驗收完成，不宣稱 99／100 分。

SSS 初始安裝入口只用於尚未建立更新儲存區的電腦；既有儲存區使用正常更新流程。登入啟動已登錄，真正下次登入啟動仍須驗收。SSL 0.6.9 僅為已封存的離線中間候選，禁止部署。

本儲存庫只發佈程式及公開發行資料。請勿上傳設備密碼、私鑰、授權設定、門市連線設定或營業資料。
