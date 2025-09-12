rule Trojan_Win32_ClipBanker_BA_2147744791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BA!MTB"
        threat_id = "2147744791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BCH_P2PKH_CashAddr" ascii //weight: 1
        $x_1_2 = "BTC_BECH32" ascii //weight: 1
        $x_1_3 = "VERTCOIN" ascii //weight: 1
        $x_1_4 = "NAMECOIN" ascii //weight: 1
        $x_1_5 = "GetSimilarAddress" ascii //weight: 1
        $x_1_6 = "WriteAllBytes" ascii //weight: 1
        $x_1_7 = "DownloadString" ascii //weight: 1
        $x_1_8 = "STEAM_URL" ascii //weight: 1
        $x_1_9 = "ProcessThreadCollection" ascii //weight: 1
        $x_1_10 = "BlockCCW" ascii //weight: 1
        $x_1_11 = "Clipboard" ascii //weight: 1
        $x_1_12 = "System.Text.RegularExpressions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_OV_2147754510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.OV!MTB"
        threat_id = "2147754510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 35 fc fe ff ff 03 ca 81 e1 ff 00 00 80 79 ?? 49 81 c9 ?? ?? ?? ?? 41 0f b6 84 0d fc fe ff ff 8b 8d f8 fe ff ff 43 30 44 19 ff 3b 5d 0c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RA_2147755650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RA!MTB"
        threat_id = "2147755650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "marie\\Desktop\\clipmonitor KETHAS FINAL EVERYTHING FIXED\\clipmonitor" ascii //weight: 1
        $x_1_2 = "CLIPBOARD: '' vs. ''" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RA_2147755650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RA!MTB"
        threat_id = "2147755650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "http://74.cz" wide //weight: 1
        $x_1_3 = "GetTextExtentPoint32A" ascii //weight: 1
        $x_1_4 = "ShellExecuteExA" ascii //weight: 1
        $x_1_5 = "SHGetPathFromIDListA" ascii //weight: 1
        $x_1_6 = "(ShlObj" ascii //weight: 1
        $x_1_7 = "UrlMon" ascii //weight: 1
        $x_1_8 = "C:\\ProgramData\\MyApp\\" ascii //weight: 1
        $x_1_9 = "It's like strapping a rocket engine to a minivan." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GA_2147773591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GA!MTB"
        threat_id = "2147773591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "47"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Clipboard" ascii //weight: 10
        $x_10_2 = "AddClipboardFormatListener" ascii //weight: 10
        $x_1_3 = "WM_CLIPBOARDUPDATE" ascii //weight: 1
        $x_1_4 = "currentClipboard" ascii //weight: 1
        $x_10_5 = "Regex" ascii //weight: 10
        $x_1_6 = "bitcoin" ascii //weight: 1
        $x_1_7 = "ethereum" ascii //weight: 1
        $x_1_8 = "monero" ascii //weight: 1
        $x_1_9 = "ripple" ascii //weight: 1
        $x_1_10 = "bitcoincash" ascii //weight: 1
        $x_1_11 = "litecoin" ascii //weight: 1
        $x_1_12 = "binance" ascii //weight: 1
        $x_1_13 = "tezos" ascii //weight: 1
        $x_10_14 = "\\b(bitcoincash)" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClipBanker_MR_2147776634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.MR!MTB"
        threat_id = "2147776634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 14 30 0f [0-4] 81 [0-5] c1 [0-2] 03 ?? 8a [0-2] 88 [0-2] 40 3b c1 7c e1}  //weight: 5, accuracy: Low
        $x_1_2 = "clrjit.dll" ascii //weight: 1
        $x_1_3 = "CLRCreateInstance" ascii //weight: 1
        $x_1_4 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_5 = "ResourceAssembly" ascii //weight: 1
        $x_1_6 = "formSubmitURL" ascii //weight: 1
        $x_1_7 = "encryptedPassword" ascii //weight: 1
        $x_1_8 = "http://bot.whatismyipaddress.com/" ascii //weight: 1
        $x_1_9 = "AntiviruHuflepuffsProduct" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet" ascii //weight: 1
        $x_1_11 = "shell\\open\\command" ascii //weight: 1
        $x_1_12 = "BCryptDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClipBanker_JB_2147784195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.JB!MTB"
        threat_id = "2147784195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4TYAtCFTXC6oDwB3iyL5vxnFWqGtwPY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_JB_2147784195_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.JB!MTB"
        threat_id = "2147784195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URTEWND0Q" ascii //weight: 1
        $x_1_2 = "OpenClipboard" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "SetClipboardData" ascii //weight: 1
        $x_1_5 = "CreateMutexA" ascii //weight: 1
        $x_1_6 = "DeFmGMARHz2YdhTJ3RMSyYH7uNSn5RrdK" ascii //weight: 1
        $x_1_7 = "3GFVhpmkmmRns96u56xkNCs8HQtMaJGND" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RT_2147786574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RT!MTB"
        threat_id = "2147786574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8b f8 59 8b f2 8a 0c 75 ?? ?? ?? ?? 88 0c 3e 46 3b f3 72 ?? 8b c2 83 e0 0f 8a 80 ?? ?? ?? ?? 30 04 3a 42 3b d3 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RT_2147786574_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RT!MTB"
        threat_id = "2147786574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 9b 01 00 00 85 c0 74 ?? 8b 0d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 04 01 88 02 8b 0d ?? ?? ?? ?? 83 c1 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RM_2147787586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RM!MTB"
        threat_id = "2147787586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 c4 7e 00 00 8b 55 ?? 8b 02 2b c1 8b 4d ?? 89 01 8b 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RM_2147787586_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RM!MTB"
        threat_id = "2147787586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 c4 eb f8 1c 8a 0c 01 89 5c 24 ?? 88 0c 02 69 54 24 ?? 27 e2 d0 4b 89 54 24 ?? 83 c0 01 8b 54 24 ?? 39 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RM_2147787586_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RM!MTB"
        threat_id = "2147787586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f6 b1 81 29 75 8b 4c 24 ?? 89 4c 24 ?? 39 f0 75 ?? 66 b8 50 d4 66 8b 4c 24 ?? 8b 54 24 ?? 89 54 24 ?? 66 39 c8 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RM_2147787586_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RM!MTB"
        threat_id = "2147787586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 5d fc c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5b 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 c4 7e 00 00 8b 55 ?? 8b 02 2b c1 8b 4d ?? 89 01 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 4c 10 ?? 89 0d ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_DE_2147787831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.DE!MTB"
        threat_id = "2147787831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RemoveClipboardFormatListener" ascii //weight: 1
        $x_1_2 = "bitcoincash:" ascii //weight: 1
        $x_1_3 = "GetClipboardOwner" ascii //weight: 1
        $x_1_4 = "ChangeClipboardChain" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "PostMessageW" ascii //weight: 1
        $x_1_7 = "!!mp!!mp!!mp!!mp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BF_2147788496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BF!MTB"
        threat_id = "2147788496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pyi-windows-manifest-filename crypto-yank.exe.manifest" ascii //weight: 1
        $x_1_2 = "email._encoded_words" ascii //weight: 1
        $x_1_3 = "http.cookiejar" ascii //weight: 1
        $x_1_4 = "email.base64mime" ascii //weight: 1
        $x_1_5 = "multiprocessing.resource_tracker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_EA_2147788928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.EA!MTB"
        threat_id = "2147788928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 41 6f 66 31 44 4d c4 41 83 f9 1d 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_EA_2147788928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.EA!MTB"
        threat_id = "2147788928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "01101001 01110100 01110011 01101100 01100001 01110101 01110010 01100101 01101110 01100101 01101100 01101001 01111010 01000000" ascii //weight: 1
        $x_1_2 = "01101110 00100000 00111101 00100000 01000100 011010" ascii //weight: 1
        $x_1_3 = "you got hacked you got hacked you got hacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_M_2147789010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.M!MTB"
        threat_id = "2147789010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CrashDumps" ascii //weight: 3
        $x_3_2 = "subst.exe" ascii //weight: 3
        $x_3_3 = "schtasks" ascii //weight: 3
        $x_3_4 = "/Create /tn NvTmRep_CrashReport3_{B2FE1952-0186} /sc MINUTE /tr" ascii //weight: 3
        $x_3_5 = "08841d-18c7-4e2d-f7e29d" ascii //weight: 3
        $x_3_6 = "ProcessHacker.exe" ascii //weight: 3
        $x_3_7 = "Users\\youar" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_ABM_2147789558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.ABM!MTB"
        threat_id = "2147789558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "@ C O M R" ascii //weight: 3
        $x_3_2 = "IcmpCreateFile" ascii //weight: 3
        $x_3_3 = "InternetQueryDataAvailable" ascii //weight: 3
        $x_3_4 = "WNetUseConnectionW" ascii //weight: 3
        $x_3_5 = "GetUserObjectInformationW" ascii //weight: 3
        $x_3_6 = "DestroyEnvironmentBlock" ascii //weight: 3
        $x_3_7 = "CoTaskMemAlloc" ascii //weight: 3
        $x_3_8 = "WSOCK32.dll" ascii //weight: 3
        $x_3_9 = "5gIkvU5" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_EF_2147794184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.EF!MTB"
        threat_id = "2147794184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "StartGrabbing" ascii //weight: 3
        $x_3_2 = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii //weight: 3
        $x_3_3 = "^0x[a-fA-F0-9]{40}$" ascii //weight: 3
        $x_3_4 = "retrieve_Info" ascii //weight: 3
        $x_3_5 = "installed the clipper" ascii //weight: 3
        $x_3_6 = "yourBCHAddress" ascii //weight: 3
        $x_3_7 = "DownloadString" ascii //weight: 3
        $x_3_8 = "sendToHook" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AM_2147794189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AM!MTB"
        threat_id = "2147794189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Release\\troce.pdb" ascii //weight: 3
        $x_1_2 = "Desktop\\1" ascii //weight: 1
        $x_1_3 = "IsClipboardFormatAvailable" ascii //weight: 1
        $x_1_4 = "OpenClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_QMS_2147794585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.QMS!MTB"
        threat_id = "2147794585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileDelete, %A_ScriptDir%\\SN.txt" ascii //weight: 1
        $x_1_2 = "click(786, 288,0.4,250)" ascii //weight: 1
        $x_1_3 = "click(779,400,0.4,250)" ascii //weight: 1
        $x_1_4 = "#32768 ahk_exe AutoHotkey.exe" ascii //weight: 1
        $x_1_5 = "ychqwer123" ascii //weight: 1
        $x_1_6 = "GetHash(str,v)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_QNV_2147794626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.QNV!MTB"
        threat_id = "2147794626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\src\\Solarion2018\\Bin32\\" ascii //weight: 1
        $x_1_2 = {8b 07 83 c4 04 c1 e0 04 89 07 8b 47 04 c1 e0 04 89 47 04 8b 02 c7 47 0c ff 00 00 00 c1 e0 04 5f 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_D_2147795755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.D!MTB"
        threat_id = "2147795755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://185.215.113.93" ascii //weight: 1
        $x_1_2 = "egege7eg7g7g575h7eg7h7g" wide //weight: 1
        $x_1_3 = "U24188479" ascii //weight: 1
        $x_1_4 = "E27440746" ascii //weight: 1
        $x_1_5 = "B23181897" ascii //weight: 1
        $x_1_6 = "bitcoincash:q" ascii //weight: 1
        $x_1_7 = "cosmos1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_D_2147795755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.D!MTB"
        threat_id = "2147795755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\wtu" ascii //weight: 1
        $x_1_2 = "llsdkj3e0pr" ascii //weight: 1
        $x_1_3 = "D3416DA40338fAf9E772388A93fAF5059bFd5" ascii //weight: 1
        $x_1_4 = "19PiS9rjuviWadjYbM7m9UzEszBBjiiden" ascii //weight: 1
        $x_1_5 = "1ChgsGiUC77Kib1jGCdeunptnSwd3Vvv4R" ascii //weight: 1
        $x_1_6 = "1DfnvEs9EqUpUw2dw4ugJhJw2KfU7cLWnY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AD_2147797738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AD!MTB"
        threat_id = "2147797738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Antidetect browser for general purpose" ascii //weight: 3
        $x_3_2 = "Denis Zhitnyakov" ascii //weight: 3
        $x_3_3 = "NETWORK_DOWN" ascii //weight: 3
        $x_3_4 = "Oreans.vxd" ascii //weight: 3
        $x_3_5 = "Software\\Wine" ascii //weight: 3
        $x_3_6 = "%userappdata%\\RestartApp.exe" ascii //weight: 3
        $x_3_7 = "2DJS2" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GGL_2147799496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GGL!MTB"
        threat_id = "2147799496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 30 89 31 8b 70 04 89 71 04 8b 71 18 89 71 08 83 c0 10 83 c1 10 3b 43 08 72 e5}  //weight: 10, accuracy: High
        $x_1_2 = "select source,function,upvars,name,currentline,activelines" ascii //weight: 1
        $x_1_3 = "mogu.exe" ascii //weight: 1
        $x_1_4 = "Copyright (C) wyongk 2021" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_DP_2147807562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.DP!MTB"
        threat_id = "2147807562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 24 8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb cb}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 fc 73 13 8b 4d f0 03 4d f8 8b 55 f8 8b 45 e8 8a 14 50 88 11 eb dc}  //weight: 1, accuracy: High
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPB_2147809351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPB!MTB"
        threat_id = "2147809351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Clipper" ascii //weight: 1
        $x_1_2 = "/Create /tn MicrosoftDriver /sc MINUTE /tr" ascii //weight: 1
        $x_1_3 = "card.php" ascii //weight: 1
        $x_1_4 = "username" ascii //weight: 1
        $x_1_5 = "Mozilla" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_MD_2147809801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.MD!MTB"
        threat_id = "2147809801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b 55 f8 8b 04 8a 50 8d 8d f0 fe ff ff 51 ff 15 ?? ?? ?? ?? 68 00 01 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 85 ec fe ff ff 8b 55 fc 8b 45 f4 8b 8d ec fe ff ff 89 0c ?? 68 80 00 00 00 8b 55 fc 8b 45 f4 8b 0c ?? 51 6a ff 8d 95 f0 fe ff ff 52 6a 00 6a 00 ff 15 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {89 65 f0 c7 85 cc fd ff ff 00 00 00 00 c7 85 bc fd ff ff 00 00 00 00 c7 85 c4 fd ff ff 00 00 00 00 c7 85 c0 fd ff ff 00 00 00 00 c7 85 b8 fd ff ff 00 00 00 00 c7 85 e0 fd ff ff 00 00 00 00 c7 85 b4 7d ff ff 00 00 00 00 c7 45 ec 00 00 00 00 c7 85 c8 fd ff ff 00 00 00 00 66 c7 85 b8 7d ff ff 00 00 b9 ff 1f 00 00 33 c0 8d bd ba 7d ff ff f3 ab 66 ab 66 c7 85 e4 fd ff ff 00 00 b9 81 00 00 00 33 c0 8d bd e6 fd ff ff f3 ab 66 ab 66 c7 85 d0 fd ff ff 00 00 33 c0 89 85 d2 fd ff ff 89 85 d6 fd ff ff 89 85 da fd ff ff 66 89 85 de fd ff ff c7 45 fc 00 00 00 00 6a 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GQ_2147812772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GQ!MTB"
        threat_id = "2147812772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.215.113.8" ascii //weight: 1
        $x_1_2 = "tsrv3.ru" ascii //weight: 1
        $x_1_3 = "tsrv4.ws" ascii //weight: 1
        $x_1_4 = "tldrbox.top" ascii //weight: 1
        $x_1_5 = "tldrhaus.top" ascii //weight: 1
        $x_1_6 = "tldrzone.top" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "bitcoincash:qpx7g2fyuwq48npc3mscuzr04z6knnkj0swcy4e0xj" ascii //weight: 1
        $x_1_9 = "cosmos1fw3x9atn2vwzuvmsm57xwd6q0kev2kqdun9aft" ascii //weight: 1
        $x_1_10 = "band1cxp0d4yrdylm93nl3l5xdjmludftd49nf6lx75" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_ME_2147813145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.ME!MTB"
        threat_id = "2147813145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {de c8 44 91 d2 2e 67 15 bb ef 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "EmptyClipboard" ascii //weight: 1
        $x_1_5 = "H3c7K4c5" wide //weight: 1
        $x_1_6 = "taskkill /F /IM " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GTQ_2147813283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GTQ!MTB"
        threat_id = "2147813283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 07 89 5f 04 89 4f 08 89 57 0c 8b 45 e4 8b 4d f0 89 45 f4 81 f1 ?? ?? ?? ?? 8b 45 ec 35 ?? ?? ?? ?? 89 35 98 e2 42 00 0b c8 8b 45 e8}  //weight: 10, accuracy: Low
        $x_1_2 = "GetTimeZoneInformation" ascii //weight: 1
        $x_1_3 = "GetTokenInformation" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CC_2147815019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CC!MTB"
        threat_id = "2147815019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" ascii //weight: 3
        $x_3_2 = "BIOS System.exe" ascii //weight: 3
        $x_3_3 = "CreateMutexA" ascii //weight: 3
        $x_3_4 = "Explorer_Server" ascii //weight: 3
        $x_3_5 = "GetAsyncKeyState" ascii //weight: 3
        $x_3_6 = "GetClipboardData" ascii //weight: 3
        $x_3_7 = "IsClipboardFormatAvailable" ascii //weight: 3
        $x_3_8 = "CountClipboardFormats" ascii //weight: 3
        $x_3_9 = "EmptyClipboard" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GJ_2147816381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GJ!MTB"
        threat_id = "2147816381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "239.255.255.250" ascii //weight: 1
        $x_1_2 = "185.215.113.84" ascii //weight: 1
        $x_1_3 = "/c start .\\%s & start .\\%s\\VolDriver.exe" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "desktop.ini" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPA_2147816705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPA!MTB"
        threat_id = "2147816705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d6 68 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff d0 68 ?? ?? ?? ?? 89 45 f8 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 45 f0 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b d8 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b f8 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "/C /create /F /sc minute /mo 1 /tn" wide //weight: 1
        $x_1_3 = "mstsca.exe" wide //weight: 1
        $x_1_4 = "Azure-Update-Task" wide //weight: 1
        $x_1_5 = "C:\\Windows\\System32\\schtasks.exe" wide //weight: 1
        $x_1_6 = "kernel32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPP_2147816788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPP!MTB"
        threat_id = "2147816788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 fc 8b 4d fc 81 e1 ff 00 00 00 8b 55 08 03 55 f0 8b 45 f8 8a 12 32 14 08 8b 45 08 03 45 f0 88 10 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_XA_2147817373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.XA!MTB"
        threat_id = "2147817373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 54 24 18 33 c0 85 db 74 18 8d 0c c2 8b 74 0c ?? 8b 4c 0c ?? 31 74 c4 ?? 31 4c c4 ?? 40 3b c3 72 e8 8d 74 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 01 7c 24 14 01 7c 24 18 2b c7 89 44 24 ?? 3b c7 73 bf}  //weight: 5, accuracy: Low
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "bitcoincash:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_DA_2147817481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.DA!MTB"
        threat_id = "2147817481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 94 11 [0-4] 33 c2 8b 4d ?? 8b 91 [0-4] 8b 4d ?? 88 04 0a e9}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 8c 0e [0-4] 33 ca 8b 55 ?? 88 8c 02 [0-4] e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AHK_2147817573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AHK!MTB"
        threat_id = "2147817573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RemoveClipboardFormatListener" ascii //weight: 1
        $x_1_2 = "AddClipboardFormatListener" ascii //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
        $x_1_4 = "objOSItem.SerialNumber" wide //weight: 1
        $x_1_5 = "objOSItem.Manufacturer" wide //weight: 1
        $x_1_6 = "GetKeyState()" ascii //weight: 1
        $x_1_7 = "OpenClipboard" ascii //weight: 1
        $x_1_8 = "CloseClipboard" ascii //weight: 1
        $x_1_9 = "GetClipboardData" ascii //weight: 1
        $x_1_10 = "EmptyClipboard" ascii //weight: 1
        $x_1_11 = "SetClipboardData" ascii //weight: 1
        $x_1_12 = ">AUTOHOTKEY SCRIPT<" ascii //weight: 1
        $x_1_13 = "Keybd hook: %s" ascii //weight: 1
        $x_1_14 = "strCSItem.Manufacturer" wide //weight: 1
        $x_1_15 = "strCSItem.NumberOfLogicalProcessors" wide //weight: 1
        $x_1_16 = "strCSItem.SerialNumber" wide //weight: 1
        $x_1_17 = "strCSItem.Domain" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_FX_2147817951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.FX!MTB"
        threat_id = "2147817951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 8d 8d ?? ?? ?? ?? 48 01 c8 48 2d a0 01 00 00 48 8b 00}  //weight: 10, accuracy: Low
        $x_10_2 = {48 89 05 65 6b 00 00 48 8b 05 5e 25 00 00 48 89 45 f0 48 8b 05 63 25 00 00 48 89 45 f8}  //weight: 10, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AJ_2147818392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AJ!MTB"
        threat_id = "2147818392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetKeyboardLayoutList" ascii //weight: 2
        $x_2_2 = "InternetCrackUrlA" ascii //weight: 2
        $x_2_3 = "PasswordsList.txt" ascii //weight: 2
        $x_2_4 = "scr.jpg" ascii //weight: 2
        $x_2_5 = "System.txt" ascii //weight: 2
        $x_2_6 = "ip.txt" ascii //weight: 2
        $x_2_7 = "Electrum\\wallets" wide //weight: 2
        $x_2_8 = "system32\\timeout.exe 3 & del" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AK_2147819129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AK!MTB"
        threat_id = "2147819129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /C \"start \"q\"" ascii //weight: 1
        $x_1_2 = "localappdata" ascii //weight: 1
        $x_1_3 = "WakeAllConditionVariable" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
        $x_1_5 = "GetClipboardSequenceNumber" ascii //weight: 1
        $x_1_6 = "Users\\Awar" ascii //weight: 1
        $x_1_7 = "clipper-main-all-crypto" ascii //weight: 1
        $x_1_8 = "Setup.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_XP_2147823192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.XP!MTB"
        threat_id = "2147823192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 5d fc 33 d2 8b c1 f7 75 0c 66 8b 04 56 66 31 04 4f 41 3b cb 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BM_2147825217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BM!MTB"
        threat_id = "2147825217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {32 c2 88 06 8a 41 01 46 fe c2 41 84 c0 75}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_DJ_2147826394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.DJ!MTB"
        threat_id = "2147826394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "main.HideWindow" ascii //weight: 1
        $x_1_3 = "main.createWallets" ascii //weight: 1
        $x_1_4 = "cryptoStealer/proccess64/main.go" ascii //weight: 1
        $x_1_5 = "proccess64/domain/App/replace.ReplaceWallet" ascii //weight: 1
        $x_1_6 = "github.com/go-telegram-bot-api/telegram-bot-api" ascii //weight: 1
        $x_1_7 = "github.com/atotto/clipboard.WriteAll" ascii //weight: 1
        $x_1_8 = "github.com/AllenDang/w32" ascii //weight: 1
        $x_1_9 = "github.com/technoweenie/multipartstreamer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_DK_2147826401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.DK!MTB"
        threat_id = "2147826401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 39 8d 49 01 2c 02 88 41 ff 83 eb 01 75}  //weight: 1, accuracy: High
        $x_1_2 = "b2357232-52b0-492f-b26f-0d36c7f096ad" ascii //weight: 1
        $x_2_3 = "dba692117be7b6d3480fe5220fdd58b38bf.xyz/API/2/configure.php?" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_DL_2147827630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.DL!MTB"
        threat_id = "2147827630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "key.cocotechnology.tech/autologin" ascii //weight: 1
        $x_1_2 = "Ready For Execution!" ascii //weight: 1
        $x_1_3 = "CocoBytecode.dll" ascii //weight: 1
        $x_1_4 = "TEMP%\\Indicium-Supra.log" ascii //weight: 1
        $x_1_5 = "@@.exe" wide //weight: 1
        $x_1_6 = "Click to break in debugger!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_R_2147829671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.R!MTB"
        threat_id = "2147829671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Silent Miner.pdb" ascii //weight: 1
        $x_1_2 = {c7 45 d4 2b 73 73 7e 0f 28 05 00 c7 40 00 0f 11 45 c4 c7 45 d8 72 70 60 28 c7 45 dc 6f 74 70 00 8a 45 b4 30 44 0d b5 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_R_2147829671_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.R!MTB"
        threat_id = "2147829671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Work\\felix\\sources\\PFelix.vbp" wide //weight: 1
        $x_1_2 = "Steam|TwelveSky|WarRock" wide //weight: 1
        $x_1_3 = "coresys.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BC_2147830885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BC!MTB"
        threat_id = "2147830885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 3b c7 85 ?? fd ff ff 00 00 00 00 8d 8d ?? fd ff ff 68 ?? ?? ?? ?? c7 85 ?? fd ff ff 00 00 00 00 c7 85 ?? fd ff ff 0f 00 00 00 c6 85 ?? fd ff ff 00 e8 13 ?? ff ff 68 ?? ?? ?? ?? c6 45 fc ?? 0f 57 c0 8b 1d}  //weight: 2, accuracy: Low
        $x_2_2 = "wscript.exe /E:jscript" ascii //weight: 2
        $x_1_3 = "RegOpenKeyExA" ascii //weight: 1
        $x_1_4 = "RegSetValueExA" ascii //weight: 1
        $x_1_5 = "RegCloseKey" ascii //weight: 1
        $x_1_6 = "FindResourceA" ascii //weight: 1
        $x_1_7 = "LoadResource" ascii //weight: 1
        $x_1_8 = "SizeofResource" ascii //weight: 1
        $x_1_9 = "LockResource" ascii //weight: 1
        $x_1_10 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPW_2147833387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPW!MTB"
        threat_id = "2147833387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "23.88.125.20" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "BibiFun" ascii //weight: 1
        $x_1_4 = "MuteKy" ascii //weight: 1
        $x_1_5 = "CreateMutexW" ascii //weight: 1
        $x_1_6 = "GetClipboardData" ascii //weight: 1
        $x_1_7 = "EmptyClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_MF_2147835877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.MF!MTB"
        threat_id = "2147835877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 25 00 c0 fa 61 b1 06 8a 4d 04 0f ab fa 80 f2 90 66 0f ba f2 86 81 c5 06 00 00 00 66 0f bd d4 80 e2 0e 36 88 08 66 0f b6 d5 66 c1 da 43 d2 f2 8b 16 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_MG_2147836527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.MG!MTB"
        threat_id = "2147836527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 b8 8b 45 b8 89 45 b4 c6 45 fc 02 68 ?? ?? ?? ?? 8d 4d 80 e8 ?? ?? ?? ?? 89 45 b0 8b 55 b4 8b 4d b0 e8 ?? ?? ?? ?? 88 45 d7 8d 4d 80 e8 ?? ?? ?? ?? c6 45 fc 01 8d 8d 68 ff ff ff e8}  //weight: 5, accuracy: Low
        $x_5_2 = "YSIBXIOYSCTRIABJKPYIWYYFQARVQJPSMGUEBVTIRYSGK" ascii //weight: 5
        $x_5_3 = "PXAWQSMKKAWVFHVMWGDAPXMWGKHVELAQISSOEWOBVZTCB" ascii //weight: 5
        $x_5_4 = "HAEMDEGIWCMIRECRUVOBRWQDHEAXWNUAWNUTXSTWTDCMT" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BH_2147837086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BH!MTB"
        threat_id = "2147837086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 33 ff 57 ff 15 ?? ?? 43 00 85 c0 74 ?? 56 6a 01 ff 15 ?? ?? 43 00 8b f0 85 f6 74 ?? 56 ff 15 ?? ?? 43 00 8b f8 57 ff 15 ?? ?? 44 00 50 57 e8 7c ?? 00 00 83 c4 0c 8b f8 56 ff 15 ?? ?? 43 00 ff 15 ?? ?? 43 00 8b c7 5e 5f c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_EB_2147837771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.EB!MTB"
        threat_id = "2147837771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "etClipboardData" ascii //weight: 1
        $x_1_2 = "reateMutexW" ascii //weight: 1
        $x_1_3 = "bc1q" wide //weight: 1
        $x_2_4 = {68 00 02 00 00 6a 40 ff 15 ?? ?? ?? ?? 68 80 00 00 00 50 6a ff 89 04 37 8d 45 84 50 53 53 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_EB_2147837771_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.EB!MTB"
        threat_id = "2147837771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateMutexA" ascii //weight: 1
        $x_1_2 = "DJSHDHFEKFDMVC" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "EmptyClipboard" ascii //weight: 1
        $x_1_5 = "OpenClipboard" ascii //weight: 1
        $x_1_6 = "SetClipboardData" ascii //weight: 1
        $x_1_7 = "CloseClipboard" ascii //weight: 1
        $x_1_8 = "kvw3e90n7a4lh0qkpj829890h62supmznyac6t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RDB_2147837812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RDB!MTB"
        threat_id = "2147837812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "punpun" ascii //weight: 1
        $x_1_2 = "AddUser:diego7770" ascii //weight: 1
        $x_1_3 = "bd34hewf" wide //weight: 1
        $x_1_4 = "79.137.196.121" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BI_2147837855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BI!MTB"
        threat_id = "2147837855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c0 0f 84 86 00 00 00 ff 75 08 ff 15 c0 41 ?? ?? 85 c0 74 79 83 65 e8 00 33 c0 c7 45 ec 07 00 00 00 66 89 45 d8 21 45 fc 8d 45 d8 50 e8 70 00 00 00 3c 01 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BR_2147843114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BR!MTB"
        threat_id = "2147843114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 3b 6d 75 ?? 80 7b 01 6f 75 ?? 80 7b 02 6e 75 ?? 80 7b 03 65 75 ?? 80 7b 04 72 75 ?? 80 7b 05 6f 75 ?? 80 7b 06 3a 75 ?? 0f b6 43 07 83 e8 34 a8 fb 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RL_2147843681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RL!MTB"
        threat_id = "2147843681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "19NzchVhQV8dJ4N4Eq7HEXG9ff8qCoLbvE" ascii //weight: 1
        $x_1_2 = "tz1Uk4xizSBDwfbr6W5DMVd23ryGQmdZfkVH" ascii //weight: 1
        $x_1_3 = "0xf9c6f849011BD33AD95047Eefb920ee9B710214a" ascii //weight: 1
        $x_1_4 = "bnb1fga0zpcwsvwv32rx6kzt8gmukwrcjm36cjsavm" ascii //weight: 1
        $x_1_5 = "bitcoincash:" ascii //weight: 1
        $x_1_6 = "bchreg:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPX_2147843755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPX!MTB"
        threat_id = "2147843755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 b9 82 00 00 00 99 f7 f9 81 c2 c8 00 00 00 52 ff 15 ?? ?? ?? ?? 33 c0 66 89 85 e8 bd ff ff 8d 85 e8 bd ff ff 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPX_2147843755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPX!MTB"
        threat_id = "2147843755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 14 56 8b 51 f8 89 54 24 2c ff d3 8b 44 24 28 83 f8 22 8b 44 24 14 0f 85 60 02 00 00 80 38 54 0f 85 52 02 00 00 8b 4c 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPX_2147843755_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPX!MTB"
        threat_id = "2147843755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 16 3b e3 8d b6 02 00 00 00 81 c9 ?? ?? ?? ?? d3 f0 0f b6 4c 25 00 66 d3 f8 8d ad 01 00 00 00 66 0f b3 e8 32 cb 9f fe c1 0f bd c2 f6 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPX_2147843755_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPX!MTB"
        threat_id = "2147843755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4d f0 30 4c 05 f1 40 83 f8 0e 72 f3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4d bc 30 4c 05 bd 40 83 f8 40 72 f3}  //weight: 1, accuracy: High
        $x_1_3 = {8a 85 60 ff ff ff 30 84 0d 61 ff ff ff 41 83 f9 10 72 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPX_2147843755_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPX!MTB"
        threat_id = "2147843755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 84 35 08 fe ff ff 88 84 3d 08 fe ff ff 88 8c 35 08 fe ff ff 0f b6 84 3d 08 fe ff ff 8b 8d 9c fc ff ff 03 c2 0f b6 c0 0f b6 84 05 08 fe ff ff 32 44 0d bc 88 84 0d a0 fd ff ff 41 89 8d 9c fc ff ff 83 f9 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPY_2147843758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPY!MTB"
        threat_id = "2147843758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 5e 14 8a 0c b8 2a ca 8b 56 10 88 4d e4 3b d3 73 19 8d 42 01 89 46 10 8b c6 83 fb 10 72 02 8b 06 88 0c 10 c6 44 10 01 00 eb 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPY_2147843758_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPY!MTB"
        threat_id = "2147843758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MykkkkS" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "tron.mhxieyi" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
        $x_1_5 = "User-Agent:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RPZ_2147843774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RPZ!MTB"
        threat_id = "2147843774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iplogger.com/1ZriL4" wide //weight: 1
        $x_1_2 = "bitcoincash" wide //weight: 1
        $x_1_3 = "taskkill /f /pid" wide //weight: 1
        $x_1_4 = "clipperror" wide //weight: 1
        $x_1_5 = "QUILCLIPPER by NZXER" wide //weight: 1
        $x_1_6 = "REGWRITE ( \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "CLIP ( \"(1|3)[1-9A-Z][1-9A-z]{32}\" , $BTC )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CAZQ_2147843980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CAZQ!MTB"
        threat_id = "2147843980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 0f be 0c 10 83 f9 ?? 75 2b ba ?? ?? ?? ?? c1 e2 ?? 8b 45 08 0f be 0c 10 83 f9 ?? 75 17 ba ?? ?? ?? ?? d1 e2 8b 45 08 0f be 0c 10 83 f9 ?? 75 04 b0 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "FirefoxMng" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RC_2147844554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RC!MTB"
        threat_id = "2147844554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TNfuYU8mTgsMVLEVWQJmLjEPmW5NhsFwfF" ascii //weight: 1
        $x_1_2 = "0x63D064cBc6e52951de537352278F2bD556A1235C" ascii //weight: 1
        $x_1_3 = {88 b6 5c e5 9f ba e7 a1 80 e5 8a 9f e8 83 bd 5c}  //weight: 1, accuracy: High
        $x_1_4 = "Release\\Clipper.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RC_2147844554_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RC!MTB"
        threat_id = "2147844554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bc1q502vafmmr5prtyfeqcutq0zzdrkzn5u2qr2y2j" ascii //weight: 1
        $x_1_2 = "0x639F45d4f1aF7768fD945db53C0f2d3198D63346" ascii //weight: 1
        $x_1_3 = "ltc1qvqxle97ecx29aa6hnrefrtwtvyk9e0w730kpyx" ascii //weight: 1
        $x_1_4 = "Clipper-5059811751\\clipper2.0.pdb" ascii //weight: 1
        $x_1_5 = "Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_EM_2147845959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.EM!MTB"
        threat_id = "2147845959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 77 02 6a 31 5b 6a 30 5f 83 c6 02 33 c0 66 39 06}  //weight: 5, accuracy: High
        $x_5_2 = {8d 77 02 6a 30 5b 6a 31 5f 83 c6 02 33 c0 66 39 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClipBanker_SPH_2147846324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.SPH!MTB"
        threat_id = "2147846324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 ec 54 00 00 00 c7 45 f8 41 00 00 00 c7 45 f4 39 00 00 00 c7 45 f0 7a 00 00 00 c7 45 e8 5a 00 00 00 8d 45 d8 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b7 c0 b9 82 00 00 00 99 f7 f9 81 c2 c8 00 00 00 52 ff 15 ?? ?? ?? ?? 33 c0 66 89 85 d0 7d ff ff 8d 85 d0 7d ff ff 50 e8 ?? ?? ?? ?? 83 c0 e7 59 3d e7 1f 00 00 77}  //weight: 1, accuracy: Low
        $x_1_2 = "kdsiquweqw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BJ_2147846839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BJ!MTB"
        threat_id = "2147846839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 ff 15 ac a3 40 00 85 c0 74 ?? 53 57 ff 15 a8 a3 40 00 8b 86 8c 04 00 00 8b 40 f8 40 50 68 00 20 00 00 ff 15 48 a0 40 00 8b d8 53 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 d0 11 42 47 a0 22 3f 5b ca 30 94 0e 2a 85 09 5a 82 f1 fb 68}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_C_2147847403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.C!MTB"
        threat_id = "2147847403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OutputVar2 = 19An5gUUSWA5jUbez5kXD2imaQDCAZ63rX" ascii //weight: 1
        $x_1_2 = "FileDelete, nr.bcn" ascii //weight: 1
        $x_1_3 = "Clipboard := RegExReplace(Clipboard, \"[0-9][0-9]" ascii //weight: 1
        $x_1_4 = "SetWorkingDir, %temp%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_SPD_2147847642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.SPD!MTB"
        threat_id = "2147847642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "13bQBDLXU2d9FismfDkrUqdEvWMLpCVE4L" wide //weight: 1
        $x_1_2 = "1EsCpm68oC2n4NVY8gqt2ady7h2MKiMqq5" wide //weight: 1
        $x_1_3 = "1JQzchgQx2YBtJzxfuaFHvfoRVmWpgc1iY" wide //weight: 1
        $x_1_4 = "1B3xg2nMUszkKmEinSwCkCndGahupJ5ePe" wide //weight: 1
        $x_1_5 = "vacjvava9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BG_2147849734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BG!MTB"
        threat_id = "2147849734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 09 77 ?? 83 ?? 10 8d 85 ?? fd ff ff 0f 43 ?? 80 38 31 74 ?? 83 ?? 10 8d 85 ?? fd ff ff 0f 43 ?? 80 38 33 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BK_2147849987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BK!MTB"
        threat_id = "2147849987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 47 e6 83 f8 09 77 ?? 8b 4d d8 8d 45 c0 83 fe 10 0f 43 c1 80 38 31 74 ?? 83 fe 10 8d 45 c0 0f 43 c1 80 38 33 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AAB_2147850253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AAB!MTB"
        threat_id = "2147850253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateMutexA" ascii //weight: 1
        $x_1_2 = "qoperib9fdh" ascii //weight: 1
        $x_1_3 = "5YwpaZj4HpHSEpSFxW7AfQR5tuk7r6bZa" ascii //weight: 1
        $x_1_4 = "GlobalAlloc" ascii //weight: 1
        $x_1_5 = "lstrcpynW" ascii //weight: 1
        $x_1_6 = "lstrcatA" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "OpenClipboard" ascii //weight: 1
        $x_1_9 = "SetClipboardData" ascii //weight: 1
        $x_1_10 = "MultiByteToWideChar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CRDD_2147850801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CRDD!MTB"
        threat_id = "2147850801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 06 00 e8 ?? ?? ?? ?? 6a 3a 88 46 01 e8 ?? ?? ?? ?? 6a 5c 88 46 02 e8 ?? ?? ?? ?? 6a 50 88 46 03 e8 ?? ?? ?? ?? 6a 72 5b 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BO_2147851484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BO!MTB"
        threat_id = "2147851484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 04 8b 45 fc 50 e8 ?? ?? ff ff 83 c4 04 0f b6 c8 85 c9 74 ?? 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 04 8b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CBV_2147851571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CBV!MTB"
        threat_id = "2147851571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vhsposion.xyz" ascii //weight: 1
        $x_1_2 = "146.19.213.248" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "NewBot:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GNR_2147851752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GNR!MTB"
        threat_id = "2147851752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c6 88 5c 24 32 88 5c 24 41 89 44 24 28 57 b1 4b bb ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b de 2b c6 bf ?? ?? ?? ?? b2 d0 2b fe 88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34 78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6 44 24 41 33 c6 44 24 43 2d c6 44 24 44 74 88 54 24 46 c6 44 24 40 af c6 44 24 39 62}  //weight: 10, accuracy: Low
        $x_1_2 = "Jellybeans.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AMAA_2147890138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AMAA!MTB"
        threat_id = "2147890138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(^|\\s)[13]{1}[a-km-zA-HJ-NP-Z1-9]{25,34}($|\\s)" ascii //weight: 1
        $x_1_2 = "|\\s)bnb[a-zA-Z0-9]{38,40}($|\\s)" ascii //weight: 1
        $x_1_3 = "BtcBufR_Instance" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
        $x_1_6 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GME_2147890443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GME!MTB"
        threat_id = "2147890443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 33 c0 c7 05 ?? ?? ?? ?? 0f 00 00 00 a3 ?? ?? ?? ?? a2 ?? ?? ?? ?? c3 c7 05 ?? ?? ?? ?? 54 53 01 10 b9}  //weight: 10, accuracy: Low
        $x_1_2 = "Local\\ExitCliper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BS_2147890452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BS!MTB"
        threat_id = "2147890452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "([13][a-km-zA-HJ-NP-Z1-9]{25,34})" ascii //weight: 2
        $x_2_2 = "now the program is monitoring clipboard" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_MBJB_2147891635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.MBJB!MTB"
        threat_id = "2147891635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tunesicaworopepukecegah yojarelejatohujejizodelayalibofa kogezuninipetukerabevovatemepowo" wide //weight: 1
        $x_1_2 = "melebigosipetirujuligixe" wide //weight: 1
        $x_1_3 = "carisi" wide //weight: 1
        $x_1_4 = "Tomagemoc cehucutijunu" wide //weight: 1
        $x_1_5 = "Luvolewubaheji cegenozavisi tevedatavuka kutenojonoza getanerim" wide //weight: 1
        $x_1_6 = "Xiw suloluzaz yux" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_AV_2147892412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.AV!MTB"
        threat_id = "2147892412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"ViTRQb94A98dixrnqxTy" ascii //weight: 1
        $x_1_2 = "main.importClipboard" ascii //weight: 1
        $x_1_3 = "clipboardRead" ascii //weight: 1
        $x_1_4 = "clipboardWrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BT_2147893233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BT!MTB"
        threat_id = "2147893233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 07 83 f8 60 76 ?? 83 f8 7b 72 ?? 83 f8 40 76 ?? 83 f8 5b 72 ?? 83 f8 2f 76 ?? 83 f8 3a 73}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b7 07 66 3b 45 f0 76 ?? 66 3b 45 e0 72 ?? 66 3b 45 e8 76 ?? 66 3b 45 f4 72 ?? 66 3b 45 ec 76 ?? 66 3b 45 e4 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ClipBanker_NCB_2147899655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.NCB!MTB"
        threat_id = "2147899655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 04 9f 41 8b 55 ?? 89 45 f8 89 4d ?? eb 03 8b 4d f4 43 8b 04 9f 66 39 30}  //weight: 5, accuracy: Low
        $x_1_2 = "mpdmaslsoie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_ASC_2147900661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.ASC!MTB"
        threat_id = "2147900661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\Public\\Downloads\\TeamViewer_Service.exe" ascii //weight: 1
        $x_1_2 = "tron.mhxieyi.com" ascii //weight: 1
        $x_1_3 = "0x7C92ed6f95f3f823Aa9B3425A19C9c1430f74799" ascii //weight: 1
        $x_1_4 = "3EttzDBw124jEVieQKg2vdvWGQSpzhdeFj" ascii //weight: 1
        $x_1_5 = "Users\\Public\\Downloads\\ZTXClientn.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_LL_2147901055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.LL!MTB"
        threat_id = "2147901055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 f1 43 00 0c 03 c8 89 45 c8 3b c1 74 13 83 60 08 00 83 c0 0c eb f0 a1 28 a0 44 00 8b 4d dc 89 01 c7 45 fc ?? ?? ?? ?? e8 31 00 00 00 80 7d e6 00 75 6d 3b f7 75 39 e8 34 c3 ff ff ff 70 08 57 8b 4d e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_NN_2147901183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.NN!MTB"
        threat_id = "2147901183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rusqbxgs.000webhostapp.com/1.txt" ascii //weight: 5
        $x_1_2 = "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "schtasks.exe /create /sc" ascii //weight: 1
        $x_1_4 = "clipper-1.1\\Release\\clipper-1.1.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BU_2147902831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BU!MTB"
        threat_id = "2147902831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 02 8d 4c 24 20 83 fe ?? 0f 43 4c 24 20 42 88 04 0f 8b 7c 24 30 47 89 7c 24 30 3b 54 24 1c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_ASD_2147903149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.ASD!MTB"
        threat_id = "2147903149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3EjhjDfsu!Usvtufe!H5!STB51:7!TIB367!UjnfTubnqjoh!DB1" ascii //weight: 1
        $x_1_2 = "Users\\Public\\Downloads\\ZTXClientn.exe" ascii //weight: 1
        $x_1_3 = "iuuq;00pdtq/ejhjdfsu/dpn1D" ascii //weight: 1
        $x_1_4 = "xxx/ejhjdfsu/dpn2" ascii //weight: 1
        $x_1_5 = "EjhjDfsu!Usvtufe!Sppu!H51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GZZ_2147905108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GZZ!MTB"
        threat_id = "2147905108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5b b3 cb 64 0a 6d ef 30 76 01 fb b5 8a 3d 27 19 0e e9}  //weight: 5, accuracy: High
        $x_5_2 = {48 19 5a aa 31 36 12 58 3e 5f 1c b4 2f 50}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GZZ_2147905108_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GZZ!MTB"
        threat_id = "2147905108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 6a 0d ff 15 ?? ?? ?? ?? 89 45 e4 8b 45 e4 50 ff 15 ?? ?? ?? ?? 89 45 e0 8b 4d e0 51}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GZZ_2147905108_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GZZ!MTB"
        threat_id = "2147905108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f8 8d 44 24 ?? 50 57 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 57 6a 01 ff 15 ?? ?? ?? ?? 56 ff d3 8d 4c 24 ?? 51 8d 4c 24 ?? e8 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {8b f8 8b 54 24 ?? 52 57 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 57 6a 01 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 33 f6 ff 15}  //weight: 10, accuracy: Low
        $x_1_3 = "tron.mhxieyi.com" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ClipBanker_GZX_2147908475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GZX!MTB"
        threat_id = "2147908475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 56 33 f6 56 ff 15 ?? ?? ?? ?? 85 c0 74 48 53 57 6a 0d ff 15 ?? ?? ?? ?? 8b d8 53 ff 15 ?? ?? ?? ?? 8b f8 57 ff 15 ?? ?? ?? ?? 83 c0 e6 3d 85 0f 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BV_2147909744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BV!MTB"
        threat_id = "2147909744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}" ascii //weight: 2
        $x_2_2 = "0x[a-fA-F0-9]{40,42}" ascii //weight: 2
        $x_2_3 = "T[A-Za-z1-9]{33}" ascii //weight: 2
        $x_2_4 = "D|9)[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}" ascii //weight: 2
        $x_2_5 = "://api.telegram.org/bot" ascii //weight: 2
        $x_2_6 = "/sendMessage?chat_id=" ascii //weight: 2
        $x_2_7 = "\\\\.\\PhysicalDrive0" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_RZ_2147912872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.RZ!MTB"
        threat_id = "2147912872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GeyZoneUpdateCheck" wide //weight: 1
        $x_1_2 = "bnb1qje9p7de9kq3fn290nyx08gkhr6gdjlz00jcs3" wide //weight: 1
        $x_1_3 = "TSTVi3LaEw5PvRAmDGtExbtdb95edhgjAS" wide //weight: 1
        $x_1_4 = "UQBqhHGzyLlUXZHT521txL5Wgff2nnTGFMk-FffhfGJrbQqy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BX_2147913788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BX!MTB"
        threat_id = "2147913788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://api.telegram.org/bot" ascii //weight: 2
        $x_2_2 = "/sendMessage?chat_id=" ascii //weight: 2
        $x_2_3 = "(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$)" ascii //weight: 2
        $x_2_4 = "0x[a-fA-F0-9]{40,42}$)" ascii //weight: 2
        $x_2_5 = "T[A-Za-z1-9]{33})" ascii //weight: 2
        $x_2_6 = "(D|9)[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BY_2147913830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BY!MTB"
        threat_id = "2147913830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d ec 0f be 54 ?? ?? 8b 45 08 03 45 ?? 0f be 08 33 ca 8b 55 ?? 03 55 fc 88 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_BZ_2147913854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.BZ!MTB"
        threat_id = "2147913854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 4d d0 e8 ?? ?? fc ff 83 c0 01 50 8b f4 8b 45 c4 50 ff 15 ?? ?? 71 00 3b f4 e8 ?? ?? fc ff 50 e8 ?? ?? fc ff 83 c4 0c 8b f4 8b 45 c4 50 ff 15 ?? ?? 71 00 3b f4 e8 ?? ?? fc ff 8b f4 8b 45 c4 50 6a 01 ff 15 ?? ?? 71 00 3b f4 e8 ?? ?? fc ff 8b f4 ff 15 ?? ?? 71 00 3b f4}  //weight: 2, accuracy: Low
        $x_1_2 = "(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii //weight: 1
        $x_1_3 = "0x[a-fA-F0-9]{40}$" ascii //weight: 1
        $x_1_4 = "D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CA_2147916553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CA!MTB"
        threat_id = "2147916553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 55 f7 8d 45 d4 89 14 24 89 c1 e8 ?? ?? 00 00 83 ec 04 8d 45 dc 8d 55 d4 89 14 24 89 c1 e8 ?? ?? 00 00 83 ec 04 8d 45 dc 89 04 24 8b 4d 08 e8 ?? ?? 00 00 83 ec 04 8d 45 dc 89 c1 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CB_2147916723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CB!MTB"
        threat_id = "2147916723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f0 50 e8 ?? 02 00 00 83 c4 04 89 45 ec 8b 45 ec 83 f8 1a 0f ?? ?? 00 00 00 8b 45 ec 83 f8 23 0f ?? ?? 00 00 00 8b 45 f0 0f be 08 83 f9 31 0f ?? ?? 00 00 00 8b 45 f4 89 45 f0 e8 ?? 02 00 00 8b 45 f0 50 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CB_2147916723_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CB!MTB"
        threat_id = "2147916723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bc1qvfwq2xw8nfksegk3e7zmll0p5l2e306kpt9k5p" wide //weight: 2
        $x_2_2 = "3F9R5aojt3NcE6bXkU92RQ7Y2dyaGEkGjd" wide //weight: 2
        $x_2_3 = "rfP8ruvDkjcqemnWXatLREqiy2heFeMBTc" wide //weight: 2
        $x_2_4 = "XhFp3ctWT7hvXPhCUKDuEEk7Dbqf2fXcdY" wide //weight: 2
        $x_2_5 = "17vPx2X9W2Gb4HKu1AxCvbcEVa77G38fYX" wide //weight: 2
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CD_2147917153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CD!MTB"
        threat_id = "2147917153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "(([13][a-km-zA-HJ-NP-Z0-9]{26,33},*)|(bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87}),*))" ascii //weight: 2
        $x_2_2 = "T[a-zA-Z0-9]{33}" ascii //weight: 2
        $x_2_3 = "0x[a-fA-F0-9]{40}" ascii //weight: 2
        $x_4_4 = "ClipChanged [%s]" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_CE_2147917282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.CE!MTB"
        threat_id = "2147917282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 02 8b f1 c6 85 cb fc ff ff 00 c7 85 cc fc ff ff 2c 02 00 00 ff 15 ?? 00 02 10 8b f8 8d 85 cc fc ff ff 50 57 ff 15 ?? 00 02 10 85 ?? 74 63 53 8b 1d ?? 00 02 10 0f 1f 00 6a 00 6a 00 68 04 01 00 00 8d 85 f8 fe ff ff 50 6a ff 8d 85 f0 fc ff ff 50 6a 00 6a 00 ff 15 ?? 00 02 10 83 7e 14 0f 8b c6 76 ?? 8b 06 50 8d 85 f8 fe ff ff 50 e8 ?? ?? 00 00 83 c4 08 85 c0 74 10 8d 85 cc fc ff ff 50 57 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GNT_2147922879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GNT!MTB"
        threat_id = "2147922879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "89.119.67.154/" ascii //weight: 2
        $x_2_2 = "kukutrustnet777.info" ascii //weight: 2
        $x_1_3 = "MZtiByGWi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_NIT_2147931300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.NIT!MTB"
        threat_id = "2147931300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "shecvbz" ascii //weight: 2
        $x_2_2 = "owner dead" ascii //weight: 2
        $x_1_3 = "FlushProcessWriteBuffers" ascii //weight: 1
        $x_1_4 = "ppVirtualProcessorRoots" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_NITA_2147932219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.NITA!MTB"
        threat_id = "2147932219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 6a 02 e8 c9 f6 05 00 8b f8 83 ff ff 74 7d 8d 4c 24 28 51 57 c7 44 24 30 2c 02 00 00 e8 a9 f6 05 00 3b c3 74 5f 8b 2d 88 52 50 00 8b 44 24 14 3b c3 75 05 b8 d0 6a 50 00 50 8d 54 24 50 52 e8 f5 24 04 00 83 c4 08 85 c0 75 27 8b 44 24 30 50 53 68 ff 0f 1f 00 ff d5 8b f0 3b f3 74 0f 53 56 ff 15 8c 52 50 00 56 ff 15 88 53 50 00 be 01 00 00 00 8d 4c 24 28 51 57 e8 48 f6 05 00 3b c3}  //weight: 2, accuracy: High
        $x_1_2 = {56 57 8b f1 8b 46 20 6a 64 50 ff 15 08 56 50 00 8d 7e 74 68 84 60 50 00 57 e8 82 ff ff ff 83 c4 08 8d 4e 7c 84 c0 74 07 68 64 60 50 00 eb 05 68 40 60 50 00 e8 ca 3f 0a 00 68 84 60 50 00 57 e8 5c ff ff ff 83 c4 08 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GNQ_2147934556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GNQ!MTB"
        threat_id = "2147934556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 32 ea 41 0f 4b eb}  //weight: 5, accuracy: High
        $x_5_2 = {41 52 49 ff c2 41 d0 ea 44 31 34 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_FAA_2147936777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.FAA!MTB"
        threat_id = "2147936777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f be 08 33 ca 8b 55 08 03 55 f8 88 0a eb ?? 8b 45 08 03 45 f8 0f be 08 f7 d1 8b 55 08 03 55 f8 88 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_ACI_2147937977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.ACI!MTB"
        threat_id = "2147937977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 01 00 00 00 8d 45 fc 50 68 06 00 02 00 6a 00 68 21 81 40 00 68 01 00 00 80}  //weight: 1, accuracy: High
        $x_2_2 = {53 56 57 33 db 8b 75 08 8b fb 8b c7 66 83 c0 78 0f b7 d0 52 56 e8 ?? ?? ?? ?? 66 81 c7 82 00 0f b7 cf}  //weight: 2, accuracy: Low
        $x_3_3 = "NP-0000-0000000-0000-0CaOrRAe" ascii //weight: 3
        $x_4_4 = "Software\\edisys\\eNotePad" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_SL_2147940309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.SL!MTB"
        threat_id = "2147940309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_2 = "SvcHostUpdate" ascii //weight: 2
        $x_2_3 = "SvcHostSys" ascii //weight: 2
        $x_2_4 = "start C:\\Windows\\Runtime Broker.exe" ascii //weight: 2
        $x_2_5 = "C:\\Windows\\System32\\svchost" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GVB_2147941184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GVB!MTB"
        threat_id = "2147941184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 83 ec ?? c6 45 ?? 4c c6 45 ?? 6f c6 45 ?? 61 c6 45 ?? 64 c6 45 ?? 4c c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 72 c6 45 ?? 61 c6 45 ?? 72 c6 45 ?? 79 c6 45 ?? 45 c6 45 ?? 78 c6 45 ?? 41 c6 45 ?? 00 c6 45 ?? 6b c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 00 6a 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "Tgbot/Telegram Bot Base/bin" ascii //weight: 1
        $x_1_3 = "main.fetchAndDecrypt" ascii //weight: 1
        $x_1_4 = "main.trySend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_NJH_2147943446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.NJH!MTB"
        threat_id = "2147943446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "121>1G1R1\\1b1h1n1" ascii //weight: 2
        $x_1_2 = "GetClipboardSequenceNumber" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "GlobalUnlock" ascii //weight: 1
        $x_1_5 = {01 d8 89 d1 21 f1 09 d6 0f af f1 01 c6 89 f0 83 e0 fc 89 f1 83 e1 02 89 f2 83 ca 02 0f af d1 83 f1 02 0f af c8 01 ca}  //weight: 1, accuracy: High
        $x_1_6 = {89 c1 83 c9 01 21 d1 83 f0 01 8d 1c 48 89 de 83 e6 02 89 f2 83 f2 02 89 54 24 04 89 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClipBanker_GXF_2147952147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClipBanker.GXF!MTB"
        threat_id = "2147952147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 3f 56 ff 76 20 6a 00 6a fd 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 57 6a 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 56 ff 15 ?? ?? ?? ?? 47 03 f6 83 ff 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

