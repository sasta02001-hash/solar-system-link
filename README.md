# Solar System Link

Solar System Link 與 Solar System Shield（SSS）的 Windows 安裝檔及公開更新發行區。

| 產品 | 目前可下載版本 | 下載與適用範圍 |
| --- | --- | --- |
| SSL 主控 | 0.6.8.0，更新序號 3 | [簽章執行期與版本資料](https://github.com/sasta02001-hash/solar-system-link/releases/tag/ssl-v0.6.8.0)，供既有可信 Launcher／Updater 線上更新。 |
| SSL Windows／POS 被控端 | 0.6.8-r1 | [安裝精靈及 ZIP](https://github.com/sasta02001-hash/solar-system-link/releases/tag/ssl-pos-v0.6.8-r1)，Windows x64 手動分享開發測試版。 |
| SSS 防火牆介面候選 | 0.4.5 UX | [自動選版安裝 EXE](https://github.com/sasta02001-hash/solar-system-link/releases/download/sss-ux-0.4.5-r2/SSS-0.4.5-UX-Auto-Setup-r3.exe)／[Win7、Win10／11 版本與 ZIP](https://github.com/sasta02001-hash/solar-system-link/releases/tag/sss-ux-0.4.5-r2)。Windows 7 SP1、Windows 10／11 x64，需 .NET Framework 4.8；安裝器會核對實際環境。 |

SSL 既有更新通道已發行簽章版本。更新器以固定發行公鑰、長度與 SHA-256 核對執行檔，保留前版以及原設備身分與綁定資料。

SSL 0.7.0 正在整合啟動前連網核對最新版、連線前先檢查本地及對端 SSS、更新後重開與重連；目前尚未發行或在 POS 驗收。0.6.9 離線候選已因自動重連缺陷封存，請勿部署。

SSS 0.4.5 是介面與相容安裝候選，尚不包含後續背景更新／監督橋接。SSS 原生防護、完整無人值守，以及 POS 實際持續鍵鼠操作仍須驗收；下載與開發測試通過不代表實機驗收完成。

本儲存庫只發佈程式及公開發行資料。請勿上傳設備密碼、私鑰、授權設定、門市連線設定或營業資料。
