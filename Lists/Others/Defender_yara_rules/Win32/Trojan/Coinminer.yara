rule Trojan_Win32_Coinminer_QF_2147726283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.QF"
        threat_id = "2147726283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {aa 33 c0 80 74 05 e0 aa 40 83 f8 0d 72}  //weight: 1, accuracy: High
        $x_1_2 = "Gimli.job" wide //weight: 1
        $x_1_3 = "-a cryptonight -o stratum+tcp://" wide //weight: 1
        $x_1_4 = "antivirus found" ascii //weight: 1
        $x_1_5 = "/c taskkill /f /pid " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_QQ_2147727625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.QQ"
        threat_id = "2147727625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://blockchain.info/address/" wide //weight: 3
        $x_3_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 3
        $x_1_3 = "System /v EnableLUA /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_4 = "powercfg.exe -h off" ascii //weight: 1
        $x_1_5 = "netsh firewall set opmode mode=disable" ascii //weight: 1
        $x_1_6 = "netsh advfirewall set allprofiles state off" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Coinminer_PA_2147742912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.PA!MTB"
        threat_id = "2147742912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "SQLAGENTSWW.exe" ascii //weight: 4
        $x_4_2 = "XMR.exe|XMRig.exe" ascii //weight: 4
        $x_4_3 = "XMRig CPU mine|XMRig OpenCL miner" ascii //weight: 4
        $x_4_4 = "Miner.exe" ascii //weight: 4
        $x_4_5 = "C:\\ProgramData\\taskmgzr.exe" ascii //weight: 4
        $x_2_6 = "XMR.exe" ascii //weight: 2
        $x_2_7 = "XMRig.exe" ascii //weight: 2
        $x_1_8 = "cmd /c taskkill /f /im taskmgr.exe" ascii //weight: 1
        $x_1_9 = "mcupdui.exe" ascii //weight: 1
        $x_1_10 = "egui.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_4_*) and 3 of ($x_1_*))) or
            ((5 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Coinminer_SBR_2147762344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.SBR!MSR"
        threat_id = "2147762344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://c.vvvvvvvvv.ga" ascii //weight: 1
        $x_1_2 = "XMRig miner" ascii //weight: 1
        $x_1_3 = "cmd /c taskkill /f /im taskger.exe" ascii //weight: 1
        $x_1_4 = "cmd /c taskkill /f /im GthUdTask.exe" ascii //weight: 1
        $x_1_5 = "cmd /c taskkill /f /im WavesSys.exe" ascii //weight: 1
        $x_1_6 = "cmd /c taskkill /f /im wscript.exe" ascii //weight: 1
        $x_1_7 = "cmd /c taskkill /f /im SQLAGENTSWC.exe" ascii //weight: 1
        $x_1_8 = "C:\\RECYCLER\\svchostl.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_SIB_2147781951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.SIB!MTB"
        threat_id = "2147781951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "stratum+tcp://" ascii //weight: 50
        $x_10_2 = "miner.fee.xmrig.com" ascii //weight: 10
        $x_10_3 = "emergency.fee.xmrig.com" ascii //weight: 10
        $x_1_4 = {89 f5 8b 74 24 ?? f7 d5 89 eb 89 fd 8b 7c 24 ?? 21 c3 f7 d5 89 e9 89 dd 8b 9c 24 ?? ?? ?? ?? 21 d1 31 dd 89 ac 24}  //weight: 1, accuracy: Low
        $x_1_5 = {89 dd 8b 9c 24 ?? ?? ?? ?? f7 d5 f7 d6 89 ea 89 f0 8b b4 24 ?? ?? ?? ?? 21 da 89 d5 8b 54 24 ?? 21 f0 33 44 24 ?? f7 d6 31 d5 89 ac 24}  //weight: 1, accuracy: Low
        $x_1_6 = {89 d8 8b 5c 24 ?? f7 d0 89 c2 89 f0 8b 74 24 ?? 21 da 8b 5c 24 ?? f7 d0 23 44 24 ?? 89 d7 33 44 24 ?? 31 df 8b 5c 24 00 89 7c 24}  //weight: 1, accuracy: Low
        $x_1_7 = {89 c8 8b 8c 24 ?? ?? ?? ?? f7 d0 89 c2 89 d8 8b 9c 24 ?? ?? ?? ?? f7 d0 21 f0 33 84 24 ?? ?? ?? ?? 21 da 89 d7 8b 94 24 00 89 44 24 ?? 89 d8 31 d7 f7 d0 89 7c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Coinminer_SIB_2147781951_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.SIB!MTB"
        threat_id = "2147781951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\ProgramData\\vget.vbs" ascii //weight: 1
        $x_1_2 = "C:\\RECYCLER\\vget.vbs" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\taskger.exe" ascii //weight: 1
        $x_1_4 = "C:\\RECYCLER\\taskger.exe" ascii //weight: 1
        $x_1_5 = "C:\\ProgramData\\taskmgzr.exe" ascii //weight: 1
        $x_1_6 = "C:\\RECYCLER\\taskmgzr.exe" ascii //weight: 1
        $x_1_7 = "schtasks /Delete /TN \"Update service for Windows Service\" /F" ascii //weight: 1
        $x_1_8 = "cacls C:\\Windows\\system32\\cmd.exe /e /t /g everyone:f" ascii //weight: 1
        $x_20_9 = {33 c0 85 db 7e ?? 8b 15 ?? ?? ?? ?? 85 c0 8b 0c 82 7c ?? 8b 57 10 c1 ea 02 3b c2 7d ?? 8b 57 08 89 0c 82 40 3b c3 7c ?? 33 c0 85 db 7e ?? 8b 0d b0 67 4e 00 85 c0 8b 0c 81 7c ?? 8b 55 ?? 81 c2 ?? ?? ?? ?? 8b 72 10 c1 ee 02 3b c6 7d ?? 8b 52 08 89 0c 82 40 3b c3 7c}  //weight: 20, accuracy: Low
        $x_20_10 = {8b f9 8b 87 c8 01 00 00 85 c0 8b 5c 24 ?? 8b 97 8c 01 00 00 8b 04 9a 85 c0 0f 85 ?? ?? ?? ?? 8b 87 64 01 00 00 8b 04 98 89 44 24 ?? 80 38 ?? 8b 8f 50 01 00 00 55 89 44 24 ?? 8b 34 99 56 89 74 24 ?? e8 ?? ?? ?? ?? 83 c4 04 85 c0 bd ?? ?? ?? ?? 8b 55 00 52 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8b 44 24 06 50 56 ff 15 ?? ?? ?? ?? 85 db 7c ?? 8b 8f 94 01 00 00 c1 e9 02 3b d9 7d ?? 8b 97 8c 01 00 00 89 04 9a 8b 87 8c 01 00 00 83 3c 98 00 8b 8f 8c 01 00 00 5d 83 3c 99 00 85 db 7c ?? 8b 87 80 01 00 00 c1 e8 02 3b d8 7d ?? 8b 8f 78 01 00 00 89 34 99}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 8 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Coinminer_MF_2147794628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.MF!MTB"
        threat_id = "2147794628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_2 = "payday.exe" ascii //weight: 1
        $x_1_3 = "3HAQSB4X385HTyYeAPe3BZK9yJsddmDx6A" ascii //weight: 1
        $x_1_4 = "AUhY871ZM11v6VBETgCy62hgZLdFXnUV3u" ascii //weight: 1
        $x_1_5 = "3PPkYgUp4Sh4K3Y7DeYt2ebhytGbsTMMxSE" ascii //weight: 1
        $x_1_6 = "rUaYxW6Fzsf3ryJsWfZd1DcNBxRvDh8fAd" ascii //weight: 1
        $x_1_7 = "bitcoincash:qrdeh9fzdt4uu55rp4fs2y89p37fg0jr95z03e4m0w" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_STB_2147806244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.STB!MTB"
        threat_id = "2147806244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 24 4e f7 9f 96 46 50 bf 42 03 18 31 09 ff 2e 21 d8 97 9b 6d d4 c2 b6 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_RPS_2147838900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.RPS!MTB"
        threat_id = "2147838900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "renimuse.ocry.com/renim64.exe" ascii //weight: 1
        $x_1_2 = "taskkill /f /im intelusr.exe" ascii //weight: 1
        $x_1_3 = "ping 127.0.0.1 -n 8" ascii //weight: 1
        $x_1_4 = "rst.bat" ascii //weight: 1
        $x_1_5 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_6 = "Procmon.exe" ascii //weight: 1
        $x_1_7 = "russian.lng" ascii //weight: 1
        $x_1_8 = "AnVir.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_MA_2147846017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.MA!MTB"
        threat_id = "2147846017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ":\\AnvirLab\\Mining_framework.pdb" ascii //weight: 3
        $x_3_2 = "SamaelLovesMe" wide //weight: 3
        $x_1_3 = "last_miner_link" ascii //weight: 1
        $x_1_4 = "tools/RegWriter.exe.raum_encrypted" ascii //weight: 1
        $x_1_5 = "SELECT * FROM Win32_VideoController" ascii //weight: 1
        $x_1_6 = "ROOT\\CIMV2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_RPX_2147846167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.RPX!MTB"
        threat_id = "2147846167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c9 e8 33 00 00 00 4f 01 f9 31 06 01 ff 81 ef ?? ?? ?? ?? 46 b9 ?? ?? ?? ?? 89 ff 39 de 75 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_CCJT_2147933108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.CCJT!MTB"
        threat_id = "2147933108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 61 00 c7 45 ?? 6e 00 74 00 c7 45 ?? 54 00 4e 00 c7 45 ?? 51 00 30 00 c7 45 ?? 4e 00 32 00 c7 45 ?? 54 00 61 00 c7 45 ?? 51 00 75 00 c7 45 ?? 31 00 71 00 c7 45 ?? 54 00 4e 00 c7 45 ?? 51 00 30 00 c7 45 ?? 4e 00 32 00 c7 45 ?? 54 00 61 00 c7 45 ?? 51 00 75 00 c7 45 ?? 31 00 70 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coinminer_CCJU_2147933253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinminer.CCJU!MTB"
        threat_id = "2147933253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 00 30 00 c7 45 ?? 4e 00 32 00 c7 45 ?? 54 00 61 00 c7 45 ?? 51 00 75 00 c7 45 ?? 31 00 61 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {30 32 58 25 c7 45 ?? 30 32 58 25 c7 45 ?? 30 32 58 00}  //weight: 1, accuracy: Low
        $x_1_3 = {61 70 70 64 c7 45 ?? 61 74 61 64 c7 45 ?? 2e 69 6e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

