rule Trojan_Win32_Filecoder_DSK_2147743920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.DSK!MTB"
        threat_id = "2147743920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 24 15 8a 44 24 17 0a 44 24 13 88 14 3e 83 25 ?? ?? ?? ?? 00 8a 54 24 16 88 54 3e 01 81 3d ?? ?? ?? ?? d8 01 00 00 88 44 24 17 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_NFV_2147783316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.NFV!MTB"
        threat_id = "2147783316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 ec 8b 4d dc 31 d2 f7 f1 8b 45 f4 01 d0 8b 4d e0 0f b6 09 0f b6 10 31 d1 8b 45 e4 88 08}  //weight: 5, accuracy: High
        $x_2_2 = {81 f8 00 08 00 00 b8 00 00 00 00 0f 9f c0 85 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_CH_2147807559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.CH!MTB"
        threat_id = "2147807559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Steve\\source\\repos\\CryptoLocker\\Release\\fluffy.pdb" ascii //weight: 1
        $x_1_2 = "encrypted" ascii //weight: 1
        $x_1_3 = "gbpVTF9pxlB" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
        $x_1_6 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_7 = "SHGetSpecialFolderPathW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_RPR_2147807728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.RPR!MTB"
        threat_id = "2147807728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d 54 24 40 52 6a 00 ff 15 ?? ?? ?? ?? 33 c0 8d 54 24 3c 52 50 50 50 50 89 44 24 24 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_RPX_2147812201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.RPX!MTB"
        threat_id = "2147812201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 25 00 00 00 8a 06 90 32 c2 90 88 07 90 46 90 47 90 e9 c6 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_RPY_2147812202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.RPY!MTB"
        threat_id = "2147812202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 88 07 46 47 49 83 f9 00 e9 dc ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_RPJ_2147812423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.RPJ!MTB"
        threat_id = "2147812423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 97 00 00 00 8a 06 90 32 c2 90 88 07 90 46 90 47 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {99 f7 fd 8d 42 7f 99 f7 fd 88 54 34 27 46 83 fe 38 72 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 52 8b 4d 08 8b 55 0c 81 31 ?? ?? ?? ?? f7 11 83 c1 04 4a 75 f2 5a 59}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 04 33 f7 d0 88 04 33 83 c6 01 8b 44 24 18 83 d7 00 31 fa 31 f0 09 c2 75 be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\FCVdDodDeiWxLDNDX" ascii //weight: 2
        $x_2_2 = "RECOVER" ascii //weight: 2
        $x_2_3 = "dollars in Bitcoin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\RRansom" ascii //weight: 2
        $x_2_2 = "https://iplogger.com/" ascii //weight: 2
        $x_2_3 = "SELECT * FROM SystemRestore" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BigCashForYou.exe" ascii //weight: 2
        $x_2_2 = "If you want to know more look at the attachment!" ascii //weight: 2
        $x_2_3 = "RansomWar_EOF" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "At the moment, your system is not protected." ascii //weight: 2
        $x_2_2 = "To get started, send a file to decrypt trial." ascii //weight: 2
        $x_2_3 = "tCryptoPP RNG" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Malicious code executed" ascii //weight: 2
        $x_2_2 = "Encrypting files on device with IP" ascii //weight: 2
        $x_2_3 = "Injection succeeded in process" ascii //weight: 2
        $x_2_4 = "Vyper Ransomware" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All Your Files Encrypted" ascii //weight: 2
        $x_2_2 = "Xinfecter.exe" ascii //weight: 2
        $x_2_3 = "schtasks /create /sc minute /mo" ascii //weight: 2
        $x_2_4 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "locked@onionmail.org" ascii //weight: 2
        $x_2_2 = "liveteam@onionmail.org" ascii //weight: 2
        $x_2_3 = "Your file has been encrypted" ascii //weight: 2
        $x_2_4 = "EncryptHiddenFiles" ascii //weight: 2
        $x_2_5 = "EncryptHiddenDirectories" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ARA_2147847474_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ARA!MTB"
        threat_id = "2147847474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your network has been breached and all data was encrypted. Please contact us at:" ascii //weight: 2
        $x_2_2 = "https://aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_VHO_2147896094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.VHO!MTB"
        threat_id = "2147896094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 8b 45 08 8b 4d 0c 33 f6 46 d3 e6 23 c6 5e 8b e5 5d c2 08 00}  //weight: 10, accuracy: High
        $x_10_2 = {89 06 8b 55 cc 8b 4d e0 46 49}  //weight: 10, accuracy: High
        $x_1_3 = "Mjaqgzti Gmcorktoi Yehol" ascii //weight: 1
        $x_1_4 = "Ldeokp Mnzfd Psfrweso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_RSD_2147905060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.RSD!MTB"
        threat_id = "2147905060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shadowcopy delete" ascii //weight: 1
        $x_1_2 = "clear vss" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "setting wallpaper" ascii //weight: 1
        $x_5_5 = "yarttdn.de" wide //weight: 5
        $x_5_6 = "lolol" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Filecoder_AHB_2147948764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.AHB!MTB"
        threat_id = "2147948764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 55 e0 89 54 24 14 8b 55 f0 89 54 24 10 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 1c}  //weight: 10, accuracy: Low
        $x_5_2 = "Contact me at [email address]" ascii //weight: 5
        $x_3_3 = "Pay me $1000 within 72 hours or your files will be deleted forever" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_SXA_2147948786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.SXA!MTB"
        threat_id = "2147948786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {c7 44 24 08 00 00 00 00 c7 44 24 04 ?? ?? ?? ?? 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 1c 89 45 f0 83 7d f0 ?? 74 3d c7 44 24 10 ?? ?? ?? ?? 8d 45 e0 89 44 24 0c 8b 45 ec 89 44 24 08 8b 45 e8 89 44 24 04 8b 45 f0 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec}  //weight: 6, accuracy: Low
        $x_1_2 = "ransomware" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Your files have been encrypted." ascii //weight: 1
        $x_1_5 = "To decrypt your files, send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_SXB_2147949361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.SXB!MTB"
        threat_id = "2147949361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 10 8b 45 ec 0f b6 00 31 c2 8b 45 ec 88 10 83 45 f4 ?? 8d 45 e8 89 c1}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 45 f4 3b 45 0c 7d ?? 8d 85 60 ec ff ff 8d 95 68 ec ff ff 89 14 24 89 c1}  //weight: 2, accuracy: Low
        $x_1_3 = "log.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Filecoder_ZZA_2147951836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoder.ZZA!MTB"
        threat_id = "2147951836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 ff ff ff ff ba 01 00 00 00 e8 39 2e 06 00 83 7d f4 01 75 eb 8b 4d f8 8b 55 fc 49 89 c8 49 c1 e0 20 49 83 c8 02 31 c0 85 c9 0f 95 c0 49 0f 45 d0 48 83 c4 60 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

