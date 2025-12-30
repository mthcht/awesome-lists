rule Trojan_Win32_Adload_EA_2147641874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.EA"
        threat_id = "2147641874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {be 00 40 00 00 8d ?? ?? ?? b8 ff 00 00 00 e8 ?? ?? ?? ?? 88 03 43 4e 75 f0 8d ?? ?? ?? b9 00 40 00 00 8b ?? ?? 8b 18 ff 53 10 4f 75 d3}  //weight: 3, accuracy: Low
        $x_1_2 = ".asaicache.com:" ascii //weight: 1
        $x_1_3 = ".hetodo.com:" ascii //weight: 1
        $x_1_4 = "_ch.php?uid=%s" ascii //weight: 1
        $x_1_5 = "/re.php?key=%s&ver=%s&uid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adload_A_2147694990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.A"
        threat_id = "2147694990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%dK downloaded" ascii //weight: 1
        $x_1_2 = "cs_Banner: %s" ascii //weight: 1
        $x_1_3 = "Cookie: PW_1.0=" ascii //weight: 1
        $x_1_4 = "MarketerUID: %s" ascii //weight: 1
        $x_1_5 = "\\master_idx.dtm" ascii //weight: 1
        $x_1_6 = "Checking Internet using url: %s" ascii //weight: 1
        $x_1_7 = "Client.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_RX_2147752570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.RX!MTB"
        threat_id = "2147752570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 dc 8b 45 e8 0f b6 4c 05 e4 8b 55 dc 0f b6 84 15 c8 fe ff ff 33 c8 8b 55 e8 88 4c 15 e4 e9 3d ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_DSK_2147753033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.DSK!MTB"
        threat_id = "2147753033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 0c 10 8b 15 ?? ?? ?? ?? 0f b6 84 15 ?? ?? ff ff 33 c1 8b 0d ?? ?? ?? ?? 88 84 0d ?? ?? ff ff eb 05 00 a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_RDS_2147753483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.RDS!MTB"
        threat_id = "2147753483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 03 00 00 00 f7 f1 8b 45 dc 0f be 0c 10 8b 55 f4 0f b6 44 15 ec 33 c1 8b 4d f4 88 44 0d ec eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_MR_2147753628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.MR!MTB"
        threat_id = "2147753628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 44 15 ?? 33 c1 8b 4d ?? 88 44 0d ?? eb 05 00 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_DSA_2147756794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.DSA!MTB"
        threat_id = "2147756794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 14 11 8b 35 ?? ?? ?? ?? 0f b6 3c 35 00 20 ?? ?? 89 fb 31 d3 88 1c 35 00 20 ?? ?? 81 3d ?? ?? ?? ?? ff 2b 00 00 0f 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_RW_2147797327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.RW!MTB"
        threat_id = "2147797327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "__CPPdebugHook" ascii //weight: 1
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "System Artifacts && Passwords" ascii //weight: 1
        $x_1_4 = "Passwords/Logins" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
        $x_1_6 = "Screen Capture" ascii //weight: 1
        $x_1_7 = "Detect Bitlocker Encryption" ascii //weight: 1
        $x_1_8 = "VM CPU Cores" ascii //weight: 1
        $x_1_9 = "VM Hypervisor" ascii //weight: 1
        $x_1_10 = "KillTimer" ascii //weight: 1
        $x_1_11 = "kLoaderLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_D_2147797795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.D!MTB"
        threat_id = "2147797795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 ff 34 24 59 52 89 0c 24 89 3c 24 89 e7 81 c7 04 00 00 00 81 c7 04 00 00 00 87 3c 24 5c 68 ae af fa 27 89 14 24 ba 39 73 eb 5c 81 ca ce ae f3 6f 81 c2 04 20 d7 6d f7 d2 c1 e2 05 c1 e2 02 81 f2 b6 fe 6f 16 29 d1 ff 34 24 5a 51 89 e1 81 c1 04 00 00 00 83 c1 04 87 0c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_DKL_2147808282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.DKL!MTB"
        threat_id = "2147808282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 0d cc 5c 42 01 c7 00 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 48 04 89 01 c7 80 ec ff 13 00 02 00 00 00 b9 ?? ?? ?? ?? 29 f1 89 ?? ?? ?? ?? 01 ba f0 ff 13 00 29 f2 8d 0c 02 89 0d dc 5c 42 01 83 ce 02 89 74 02 fc eb 0c c7 05 d8 5c 42 01 00 00 00 00 31 c9 89 c8 83 c4 10 5e c3}  //weight: 10, accuracy: Low
        $x_10_2 = {8b d1 c1 e9 03 0f b6 d6 b8 01 00 00 00 d3 e0 09 04 95 ?? ?? ?? ?? b8 01 00 00 00 8b ca d3 e0 09 05 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
        $x_1_3 = "Puran File Recovery.exe" ascii //weight: 1
        $x_1_4 = "KillTimer" ascii //weight: 1
        $x_1_5 = "kLoaderLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_HNU_2147809222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.HNU!MTB"
        threat_id = "2147809222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 48 04 89 01 c7 80 ec ff 13 00 02 00 00 00 b9 ?? ?? ?? ?? 29 f1 89 0d ?? ?? ?? ?? ba ?? ?? ?? ?? 29 f2 8d 0c 02 89 0d ?? ?? ?? ?? 83 ce 02 89 74 02 fc eb 0c c7 05 d8 4c 42 01 00 00 00 00 31 c9 89 c8 83 c4 ?? 5e c3}  //weight: 10, accuracy: Low
        $x_1_2 = "KillTimer" ascii //weight: 1
        $x_1_3 = "kLoaderLock" ascii //weight: 1
        $x_1_4 = "fyChangeKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_GFE_2147809629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.GFE!MTB"
        threat_id = "2147809629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 44 24 20 89 7c 24 1c 89 6c 24 18 89 5c 24 14 89 54 24 10 89 4c 24 0c 8b 44 24 24 89 44 24 08 c7 44 24 04 ?? ?? ?? ?? c7 04 24 94 e2 41 01}  //weight: 10, accuracy: Low
        $x_10_2 = {89 48 04 89 01 c7 80 ec ff 13 00 02 00 00 00 b9 ?? ?? ?? ?? 29 f1 89 0d ?? ?? ?? ?? ba ?? ?? ?? ?? 29 f2 8d 0c 02 89 0d fc bc 41 01 83 ce 02 89 74 02 fc eb 0c c7 05 f8 bc 41 01 00 00 00 00 31 c9 89 c8 83 c4 10 5e c3}  //weight: 10, accuracy: Low
        $x_1_3 = "BDCreator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_GEM_2147809828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.GEM!MTB"
        threat_id = "2147809828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b c8 8b 45 08 d3 c8 33 05 14 70 62 00 5d c3}  //weight: 10, accuracy: High
        $x_10_2 = {56 8b 35 14 70 62 00 8b ce 33 35 68 27 43 01 83 e1 1f d3 ce 85 f6 75 04}  //weight: 10, accuracy: High
        $x_1_3 = "KillTimer" ascii //weight: 1
        $x_1_4 = "DbgPrompt" ascii //weight: 1
        $x_1_5 = "DllInstall" ascii //weight: 1
        $x_1_6 = "kLoaderLock" ascii //weight: 1
        $x_1_7 = "fyChangeKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_GTM_2147814652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.GTM!MTB"
        threat_id = "2147814652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 4e fc 33 c0 a2 e7 ec 45 01 89 1e 89 46 08 c7 46 0c ?? ?? ?? ?? 89 73 10 8d 46 20 0f b7 4b 02 8d 14 08 89 53 08 03 fe 2b f9 89 7b 0c c6 03 00 89 70 fc}  //weight: 10, accuracy: Low
        $x_1_2 = "KillTimer" ascii //weight: 1
        $x_1_3 = "fyChangeKey" ascii //weight: 1
        $x_1_4 = "kLoaderLock" ascii //weight: 1
        $x_1_5 = "DbgPrompt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_EM_2147954219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.EM!MTB"
        threat_id = "2147954219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PDF-XChange Printer Standard v10.7.3.401" ascii //weight: 2
        $x_2_2 = "nsis.sf.net/NSIS_Error" ascii //weight: 2
        $x_2_3 = "Tracker Software Ltd." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Adload_EM_2147954219_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adload.EM!MTB"
        threat_id = "2147954219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PDF-XChange Printer Standard v10.7.6.404" ascii //weight: 2
        $x_2_2 = "nsis.sf.net/NSIS_Error" ascii //weight: 2
        $x_2_3 = "Tracker Software Ltd." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

