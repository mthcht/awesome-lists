rule TrojanDownloader_MSIL_CoinMiner_H_2147688596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.H"
        threat_id = "2147688596"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 00 77 00 77 00 73 00 3d 00 32 00 32 00 6c 00 71 00 76 00 6c 00 67 00 6c 00 72 00 78 00 76 00 [0-48] 32 00 70 00 6c 00 71 00 68 00 75 00 67 00 31 00 68 00 7b 00 68 00}  //weight: 1, accuracy: Low
        $x_1_2 = "kwws=22lqvlglrxvfrghu1frp2Uhydpshg2Ilohv2fj1h{h" wide //weight: 1
        $x_1_3 = {6b 00 77 00 77 00 73 00 3d 00 32 00 32 00 [0-32] 32 00 70 00 6c 00 71 00 68 00 75 00 32 00 73 00 75 00 72 00 6a 00 75 00 64 00 70 00 31 00 68 00 7b 00 68 00}  //weight: 1, accuracy: Low
        $x_1_4 = "kwws=22gxus1sz2owfilohv2plqhug1h{h" wide //weight: 1
        $x_2_5 = "ltc.exe" wide //weight: 2
        $x_2_6 = "lqvlgplqhu1h{h" wide //weight: 2
        $x_10_7 = "VRIWZDUH_Plfurvriw_Zlqgrzv_FxuuhqwYhuvlrq_Uxq" wide //weight: 10
        $x_1_8 = {6a 03 da 28 ?? 00 00 0a 0c 08 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_CoinMiner_I_2147716528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.I!bit"
        threat_id = "2147716528"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "minerd-x64-genericCompressed.dat" wide //weight: 1
        $x_1_2 = {52 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 [0-4] 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "pastebin.com" wide //weight: 1
        $x_1_4 = "-o stratum+tcp://xmg.suprnova.cc:7128 -u" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_CoinMiner_B_2147725244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.B!bit"
        threat_id = "2147725244"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "minergate-cli" wide //weight: 1
        $x_1_2 = "http://ipv4.icanhazip.com" wide //weight: 1
        $x_1_3 = "xmrig.zip|zip|xmrig|exe" wide //weight: 1
        $x_1_4 = "/api/ncin/get.php?listid=" wide //weight: 1
        $x_1_5 = "stratum+tcp://bcn.pool.minergate.com:" wide //weight: 1
        $x_1_6 = {26 00 63 00 70 00 75 00 3d 00 [0-2] 26 00 68 00 69 00 7a 00 3d 00 30 00 26 00 68 00 64 00 64 00 3d 00 [0-2] 26 00 75 00 73 00 65 00 72 00 73 00 3d 00 [0-2] 26 00 69 00 70 00 3d 00 [0-2] 26 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 73 00 3d 00 [0-2] 26 00 6d 00 69 00 6e 00 69 00 6e 00 67 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_MSIL_CoinMiner_D_2147725287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.D!bit"
        threat_id = "2147725287"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 72 75 6e 63 70 75 00 64 65 74 65 63 74 5f 67 70 75 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 43 6f 72 65 44 6c 6c 00 49 6e 73 74 61 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_4 = "https://pastebin.com/raw/" wide //weight: 10
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "\\config.json" wide //weight: 1
        $x_1_7 = "\\vbc.exe" wide //weight: 1
        $x_1_8 = "ProcessHacker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_CoinMiner_E_2147725426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.E!bit"
        threat_id = "2147725426"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 4d 6f 64 75 6c 65 31 00}  //weight: 10, accuracy: High
        $x_10_2 = "http://188.138.9.34/" wide //weight: 10
        $x_5_3 = "MicrosoftVCRuntime.exe" wide //weight: 5
        $x_5_4 = "MicrosoftRuntime.exe" wide //weight: 5
        $x_1_5 = "\" -c \"" wide //weight: 1
        $x_1_6 = "http://www.google.com" wide //weight: 1
        $x_1_7 = "winmgmts:root\\cimv2:Win32_Processor='cpu0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_CoinMiner_F_2147725702_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.F!bit"
        threat_id = "2147725702"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nvidia" wide //weight: 1
        $x_1_2 = "chrome.exe" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 78 00 61 00 78 00 61 00 78 00 61 00 2e 00 65 00 75 00 2f 00 [0-32] 2e 00 70 00 68 00 70 00 3f 00 64 00 61 00 74 00 61 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 78 00 61 00 78 00 61 00 78 00 61 00 2e 00 65 00 75 00 2f 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CoinMiner_F_2147725702_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.F!bit"
        threat_id = "2147725702"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 2f 00 65 00 74 00 63 00 2f 00 68 00 6f 00 73 00 74 00 73 00 [0-3] 31 00 39 00 38 00 2e 00 32 00 35 00 31 00 2e 00 39 00 30 00 2e 00 31 00 31 00 33 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/updated/xmrig.exe" wide //weight: 1
        $x_1_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 00 53 65 74 41 74 74 72 69 62 75 74 65 73 00 73 65 74 5f 53 65 72 76 69 63 65 4e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_MSIL_CoinMiner_BT_2147727415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.BT!bit"
        threat_id = "2147727415"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 46 6f 72 6d 31 5c 46 6f 72 6d 31 5c 6f 62 6a 5c (44 65 62|52 65 6c 65 61) 5c 46 6f 72 6d 31 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "chbre" wide //weight: 1
        $x_1_3 = "inmdw" wide //weight: 1
        $x_2_4 = "qqq.innocraft.cloud/piwik.php" wide //weight: 2
        $x_2_5 = "nabrowser.com" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_CoinMiner_BU_2147728570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.BU!bit"
        threat_id = "2147728570"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "-o http://pool.bitclockers.com:8332 -u" wide //weight: 1
        $x_1_4 = "svhost.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CoinMiner_N_2147731759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.N!bit"
        threat_id = "2147731759"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Windows\\cfmon.bat" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" wide //weight: 1
        $x_1_3 = "schtasks.exe /create /tn Timer /tr %systemroot%/lsmsrc.exe /sc onstart /ru SYSTEM" wide //weight: 1
        $x_1_4 = "root\\CIMV2" wide //weight: 1
        $x_1_5 = "SELECT * FROM Win32_PerfFormattedData_PerfProc_Process" wide //weight: 1
        $x_1_6 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 66 00 69 00 20 00 [0-2] 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 20 00 45 00 51 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CoinMiner_YRL_2147819210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.YRL!MTB"
        threat_id = "2147819210"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iex(New-Object Net.WebClient)" wide //weight: 10
        $x_10_2 = "DownloadString" wide //weight: 10
        $x_10_3 = "Invoke" ascii //weight: 10
        $x_1_4 = "axu87794.polycomusa.com/axu87794/stage1x64.ps1" wide //weight: 1
        $x_1_5 = "sicariop.polycomusa.com/sicariopExp.ps1" wide //weight: 1
        $x_1_6 = "yty0do.polycomusa.com/yty0do/stage1x64.ps1" wide //weight: 1
        $x_1_7 = "giraffebear.polycomusa.com/giraExp.ps1" wide //weight: 1
        $x_1_8 = "zhost.polycomusa.com/3xp1r3Exp.ps1" wide //weight: 1
        $x_1_9 = "host-rami.polycomusa.com/ssJFOJo4d1jQP0v/stage1x64.ps1" wide //weight: 1
        $x_1_10 = "hellmagers.polycomusa.com/stage1x64.ps1" wide //weight: 1
        $x_1_11 = "axu87794.polycomusa.com/axu87794/stage1x32.ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_CoinMiner_PZM_2147936656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CoinMiner.PZM!MTB"
        threat_id = "2147936656"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://46.8.78.172/minir.zip" ascii //weight: 5
        $x_1_2 = "taskkill /f /im browser_broker.exe" ascii //weight: 1
        $x_1_3 = "taskkill /f /im python.exe" ascii //weight: 1
        $x_1_4 = "minerlol.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

