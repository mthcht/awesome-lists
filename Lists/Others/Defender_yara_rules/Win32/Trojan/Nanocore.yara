rule Trojan_Win32_Nanocore_SD_2147734425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.SD!MTB"
        threat_id = "2147734425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 02 90 34 e2 88 45 fb 90 90 ff 75 fc 8a 45 fb 90 59 88 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b c6 03 c3 90 c6 00 e4 90 90 90 90 90 43 81 fb 2f 5c c3 1c 75 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_J_2147740902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.J!ibt"
        threat_id = "2147740902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A6C24BF5-3690-4982" wide //weight: 1
        $x_1_2 = "zip.dll" wide //weight: 1
        $x_1_3 = {78 da bc 7d 77 60 14 c5 f7 f8 de de dd ee d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_ST_2147742708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.ST!MTB"
        threat_id = "2147742708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad 85 c0 74 90 01 01 03 04 24 81 38 55 8b ec 83 75 ef 81 78 04 ec 0c 56 8d 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 0a 01 f3 [0-4] 0f ef c0 [0-4] 0f ef c9 0f 6e c0 0f 6e 0b 0f ef c1 [0-4] 51 0f 7e c1 88 c8 [0-4] 59 29 f3 [0-4] 83 c3 01 75 ?? [0-4] 89 fb [0-4] [0-4] 89 04 0a [0-4] 83 c1 01 75 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_ST_2147742708_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.ST!MTB"
        threat_id = "2147742708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_VtblGap1_45" ascii //weight: 1
        $x_1_2 = "OpenProcess" ascii //weight: 1
        $x_1_3 = "RunWorkerAsync" ascii //weight: 1
        $x_1_4 = "writeMemory" ascii //weight: 1
        $x_1_5 = "RegisterHotKey" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "GetClipboardContent" ascii //weight: 1
        $x_1_8 = "get_Fuchsia" ascii //weight: 1
        $x_1_9 = "DbDataReader" ascii //weight: 1
        $x_1_10 = "BeginInvoke" ascii //weight: 1
        $x_1_11 = "MemoryStream" ascii //weight: 1
        $x_1_12 = "DownloadString" ascii //weight: 1
        $x_1_13 = "ConfuserEx" ascii //weight: 1
        $x_1_14 = "$c111d715-6318-415a-94de-be452823c839" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_BY_2147744263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.BY!MTB"
        threat_id = "2147744263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 5e 8b 0c 1f 53 bb ?? ?? ?? ?? 81 fb 00 0f 85 ?? ?? ff ff 5b 68 ?? ?? ?? ?? 68 03 83 c4 08 16 17 eb 1a}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 ff ff 5b 4b [0-5] 8b 17 [0-5] 31 da [0-6] 39 ca 75 ?? [0-5] 6a ?? 6a 05 83 c4 08 16 17 eb 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_CMJ_2147744873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.CMJ!MTB"
        threat_id = "2147744873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 45 00 76 00 61 00 6c 00 28 00 22 00 20 00 26 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 33 00 34 00 20 00 29 00 20 00 26 00 20 00 22 00 [0-64] 22 00 20 00 26 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 33 00 34 00 20 00 29 00 20 00 26 00 20 00 22 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 45 76 61 6c 28 22 20 26 20 43 48 52 20 28 20 33 34 20 29 20 26 20 22 [0-64] 22 20 26 20 43 48 52 20 28 20 33 34 20 29 20 26 20 22 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 45 00 56 00 41 00 4c 00 20 00 28 00 20 00 22 00 [0-64] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 45 56 41 4c 20 28 20 22 [0-64] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 22 00 [0-144] 22 00 20 00 2c 00 20 00 22 00 [0-144] 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 53 54 52 49 4e 47 52 45 50 4c 41 43 45 20 28 20 22 [0-144] 22 20 2c 20 22 [0-144] 22 20 2c 20 22 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "&= STRINGREPLACE ( \"" ascii //weight: 1
        $x_1_8 = "STRINGTRIMLEFT (" ascii //weight: 1
        $x_1_9 = "BINARYLEN (" ascii //weight: 1
        $x_1_10 = "STRINGMID (" ascii //weight: 1
        $x_1_11 = "VirtualAlloc\" ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Nanocore_BA_2147745409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.BA!MTB"
        threat_id = "2147745409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winrarsfxmappingfile.tmp" ascii //weight: 10
        $x_10_2 = "GETPASSWORD1" ascii //weight: 10
        $x_10_3 = "__tmp_rar_sfx_access_check_%u" ascii //weight: 10
        $x_10_4 = ".docx" ascii //weight: 10
        $x_10_5 = ".ppt" ascii //weight: 10
        $x_10_6 = ".icm" ascii //weight: 10
        $x_10_7 = ".mp3" ascii //weight: 10
        $x_10_8 = ".pdf" ascii //weight: 10
        $x_10_9 = ".msc" ascii //weight: 10
        $x_10_10 = "Extracting files to C:\\ folder" ascii //weight: 10
        $x_10_11 = "Path=%temp%\\" ascii //weight: 10
        $x_10_12 = "ARarHtmlClassName" ascii //weight: 10
        $x_10_13 = "CryptProtectMemory failed" ascii //weight: 10
        $x_10_14 = "-el -s2 \"-d%s\" \"-sp%s\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_BE_2147745813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.BE!MTB"
        threat_id = "2147745813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winrarsfxmappingfile.tmp" ascii //weight: 10
        $x_10_2 = "GETPASSWORD1" ascii //weight: 10
        $x_10_3 = "__tmp_rar_sfx_access_check_%u" ascii //weight: 10
        $x_10_4 = ".docx" ascii //weight: 10
        $x_10_5 = ".ppt" ascii //weight: 10
        $x_1_6 = ".icm" ascii //weight: 1
        $x_1_7 = ".cpl" ascii //weight: 1
        $x_10_8 = ".mp3" ascii //weight: 10
        $x_10_9 = ".pdf" ascii //weight: 10
        $x_10_10 = ".msc" ascii //weight: 10
        $x_10_11 = "Extracting files to C:\\ folder" ascii //weight: 10
        $x_10_12 = "Path=%temp%\\" ascii //weight: 10
        $x_10_13 = "ARarHtmlClassName" ascii //weight: 10
        $x_10_14 = "CryptProtectMemory failed" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nanocore_Q_2147748018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.Q!MTB"
        threat_id = "2147748018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NanoCore Client.exe" ascii //weight: 1
        $x_1_2 = "NanoCore.ClientPluginHost" ascii //weight: 1
        $x_1_3 = "BaseCommand" ascii //weight: 1
        $x_1_4 = "FileCommand" ascii //weight: 1
        $x_1_5 = "PluginCommand" ascii //weight: 1
        $x_1_6 = "DnsRecord" ascii //weight: 1
        $x_1_7 = "AddHostEntry" ascii //weight: 1
        $x_1_8 = "DisableProtection" ascii //weight: 1
        $x_1_9 = "RestoreProtection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Nanocore_Q_2147748049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.Q!!Nanocore.gen!MTB"
        threat_id = "2147748049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "Nanocore: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NanoCore Client.exe" ascii //weight: 1
        $x_1_2 = "NanoCore.ClientPluginHost" ascii //weight: 1
        $x_1_3 = "SurveillanceExClientPlugin.dll" ascii //weight: 1
        $x_1_4 = "BaseCommand" ascii //weight: 1
        $x_1_5 = "FileCommand" ascii //weight: 1
        $x_1_6 = "PluginCommand" ascii //weight: 1
        $x_1_7 = "DnsRecord" ascii //weight: 1
        $x_1_8 = "AddHostEntry" ascii //weight: 1
        $x_1_9 = "DisableProtection" ascii //weight: 1
        $x_1_10 = "RestoreProtection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Nanocore_BF_2147748131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.BF!MTB"
        threat_id = "2147748131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "winrarsfxmappingfile.tmp" ascii //weight: 10
        $x_10_2 = "GETPASSWORD1" ascii //weight: 10
        $x_10_3 = "__tmp_rar_sfx_access_check_%u" ascii //weight: 10
        $x_10_4 = {53 00 65 00 74 00 75 00 70 00 3d 00 [0-10] 2e 00 70 00 69 00 66 00}  //weight: 10, accuracy: Low
        $x_10_5 = {53 65 74 75 70 3d [0-10] 2e 70 69 66}  //weight: 10, accuracy: Low
        $x_10_6 = ".pdf" ascii //weight: 10
        $x_10_7 = "Silent=1" ascii //weight: 10
        $x_10_8 = "Extracting files to C:\\ folder" ascii //weight: 10
        $x_10_9 = "Path=%temp%\\" ascii //weight: 10
        $x_10_10 = "ARarHtmlClassName" ascii //weight: 10
        $x_10_11 = "CryptProtectMemory failed" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Nanocore_BG_2147748622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.BG!MTB"
        threat_id = "2147748622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 a0 00 00 [0-32] 90 68 [0-32] ff d0 [0-10] b9 ?? ?? 00 00 [0-10] ff 34 0f [0-10] 31 34 24 [0-32] 8f 04 08 [0-10] 83 e9 04 [0-10] 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 b0 00 00 [0-32] ff d0 [0-10] b9 ?? ?? 00 00 [0-10] ff 34 0f [0-10] 31 34 24 [0-32] 8f 04 08 [0-10] 83 e9 04 [0-10] 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 b0 00 00 [0-32] ff d0 [0-10] b9 ?? ?? 00 00 [0-10] ff 34 0f [0-10] 31 34 24 [0-32] 8f 04 08 [0-10] 49 [0-32] 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 b0 00 00 [0-80] ff d0 [0-32] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-48] 31 34 24 [0-48] 8f 04 08 [0-10] 49 [0-48] 7d}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 b0 00 00 [0-80] ff d0 [0-48] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-48] 31 34 24 [0-80] 8f 04 08 [0-32] 49 [0-80] 0f 8d [0-48] ff e0}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 a0 00 00 [0-32] ff d0 [0-10] b9 ?? ?? 00 00 [0-10] ff 34 0f [0-10] 31 34 24 [0-32] 8f 04 08 [0-10] 49 [0-48] 7d}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 a0 00 00 [0-80] ff d0 [0-48] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-48] 31 34 24 [0-48] 8f 04 08 [0-48] 49 [0-80] 0f 8d [0-48] ff e0}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 b0 00 00 [0-80] ff d0 [0-48] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-80] 31 34 24 [0-48] 8f 04 08 [0-48] 49 [0-80] 7d 8a [0-48] ff e0}  //weight: 1, accuracy: Low
        $x_1_9 = {68 00 b0 00 00 [0-80] ff d0 [0-48] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-48] 31 34 24 [0-80] 8f 04 08 [0-96] 49 [0-80] 0f 8d [0-48] ff e0}  //weight: 1, accuracy: Low
        $x_1_10 = {68 00 b0 00 00 [0-80] ff d0 [0-48] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-80] 31 34 24 [0-48] 8f 04 08 [0-48] 49 [0-80] 7d 80 [0-48] ff e0}  //weight: 1, accuracy: Low
        $x_1_11 = {68 00 a0 00 00 [0-80] ff d0 [0-48] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-80] 31 34 24 [0-48] 8f 04 08 [0-48] 49 [0-80] 7d 80 [0-48] ff e0}  //weight: 1, accuracy: Low
        $x_1_12 = {68 00 a0 00 00 [0-80] ff d0 [0-48] b9 ?? ?? 00 00 [0-48] ff 34 0f [0-48] 31 34 24 [0-48] 8f 04 08 [0-48] 49 [0-80] 7d 80 [0-48] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Nanocore_AKN_2147750277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.AKN!MTB"
        threat_id = "2147750277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 eb 08 [0-31] 81 7d ?? ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 03 ff [0-239] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 08 [0-255] 31 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_AC_2147759225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.AC!MTB"
        threat_id = "2147759225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winrarsfxmappingfile.tmp" wide //weight: 10
        $x_10_2 = "GETPASSWORD1" wide //weight: 10
        $x_10_3 = "__tmp_rar_sfx_access_check_%u" wide //weight: 10
        $x_10_4 = ".vbs" ascii //weight: 10
        $x_1_5 = ".ppt" ascii //weight: 1
        $x_1_6 = ".icm" ascii //weight: 1
        $x_1_7 = ".cpl" ascii //weight: 1
        $x_10_8 = ".mp3" ascii //weight: 10
        $x_1_9 = ".pdf" ascii //weight: 1
        $x_1_10 = ".msc" ascii //weight: 1
        $x_10_11 = "Security warningKPlease remove %s from folder %s. It is unsecure to run %s until it is done" wide //weight: 10
        $x_10_12 = "ARarHtmlClassName" wide //weight: 10
        $x_10_13 = "CryptProtectMemory failed" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nanocore_OR_2147788921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.OR!MTB"
        threat_id = "2147788921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 0d 60 e2 ff ff 81 f9 ?? ?? ?? ?? 74 42 34 69 04 ba 04 63 2c 45 fe c8 2c 3a fe c8 04 ef 04 7f 04 9f fe c0 fe c8 04 1e 2c bf fe c8 34 7b fe c8 fe c0 fe c0 04 5f 34 22 fe c8 04 37 04 27 2c 1a 34 7c fe c0 88 84 0d 60 e2 ff ff 83 c1 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_NED_2147830477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.NED!MTB"
        threat_id = "2147830477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WydKsiPortable" ascii //weight: 1
        $x_1_2 = "Instalacja - WydKsi" ascii //weight: 1
        $x_1_3 = "Weryfikacja ustawie" ascii //weight: 1
        $x_1_4 = "XHJvb3RcY2ltdjI" wide //weight: 1
        $x_1_5 = "d2lubWdtdHM6" wide //weight: 1
        $x_1_6 = "e2ltcGVyc29uYXRpb25MZXZlbD1pbXBlcnNvbmF0ZX0hXFw" wide //weight: 1
        $x_1_7 = "Select * from Win32_Processor" wide //weight: 1
        $x_1_8 = "Archiwum" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_GPB_2147902427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.GPB!MTB"
        threat_id = "2147902427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 f9 fe ca 76 f0 3c a7 f0 f9 fe ca 76 f0 3c a7 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_GPE_2147902562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.GPE!MTB"
        threat_id = "2147902562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 23 61 23 43 68 56 00 44 23 61 23 43 68 56 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 5, accuracy: High
        $x_5_2 = {54 23 04 20 68 20 11 32 54 23 04 20 68 20 11 32 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Nanocore_SG_2147903773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.SG!MTB"
        threat_id = "2147903773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MPR.dll" ascii //weight: 1
        $x_1_2 = "Unable to open the script file." wide //weight: 1
        $x_1_3 = "hurtling.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_GPC_2147904983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.GPC!MTB"
        threat_id = "2147904983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8f e2 96 70 a3 b3 35 9f 8f e2 96 70 a3 b3 35 9f 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_GPD_2147905022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.GPD!MTB"
        threat_id = "2147905022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {10 57 63 b6 81 1f 47 5d 10 57 63 b6 81 1f 47 5d 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 5, accuracy: High
        $x_5_2 = {88 8b 98 9b 3a 24 44 10 88 8b 98 9b 3a 24 44 10 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Nanocore_NA_2147906027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.NA!MTB"
        threat_id = "2147906027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "MOUSECLICKDRAG" ascii //weight: 1
        $x_2_4 = "anaboly" ascii //weight: 2
        $x_2_5 = "palladize" ascii //weight: 2
        $x_2_6 = "FUNC V3130ORU" ascii //weight: 2
        $x_2_7 = "$N33313532WT &= CHR ( $L33313535WK6 )" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_NE_2147918604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.NE!MTB"
        threat_id = "2147918604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FOR $I = \"1\" TO $SPLIT [ \"0\" ]" ascii //weight: 1
        $x_1_2 = "$CHAR = ASC ( $SPLIT [ $I ] )" ascii //weight: 1
        $x_1_3 = "FOR $II = \"0\" TO $LEN - \"1\"" ascii //weight: 1
        $x_2_4 = "$XOR = BITXOR ( $XOR , $LEN + $II )" ascii //weight: 2
        $x_2_5 = "$RESULT &= CHRW ( $XOR )" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_SCRE_2147937240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.SCRE!MTB"
        threat_id = "2147937240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vokskrtedirigentudgravningerc" ascii //weight: 2
        $x_2_2 = "crossflowerpositionssystemssi" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nanocore_BAA_2147940673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nanocore.BAA!MTB"
        threat_id = "2147940673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 31 8d 49 01 34 ?? 88 41 ff 83 ef 01 75}  //weight: 2, accuracy: Low
        $x_2_2 = {2a c8 8b 45 08 0a d1 8b 4d e8 8b 00 88 14 01 41 89 4d e8 81 ff ?? ?? ?? ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

