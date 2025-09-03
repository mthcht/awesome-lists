rule Trojan_Win32_LummaStealer_RPX_2147845170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPX!MTB"
        threat_id = "2147845170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 d3 56 56 80 ea 13 46 d0 ca 46 f6 d2 f7 d6 fe c2 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPX_2147845170_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPX!MTB"
        threat_id = "2147845170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 b0 6a 40 68 00 30 00 00 8b 4d e4 8b 51 50 52 6a 00 8b 45 cc 50 ff 55 b0 89 45 ec 83 7d ec 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPX_2147845170_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPX!MTB"
        threat_id = "2147845170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "os_crypt.encrypted_key" ascii //weight: 1
        $x_1_2 = "Ronin Wallet" wide //weight: 1
        $x_1_3 = "Binance Chain Wallet" wide //weight: 1
        $x_1_4 = "Coinbase" wide //weight: 1
        $x_1_5 = "EnKrypt" wide //weight: 1
        $x_1_6 = "Terra Station" wide //weight: 1
        $x_1_7 = "BitClip" wide //weight: 1
        $x_1_8 = "Steem Keychain" wide //weight: 1
        $x_1_9 = "Hycon Lite Client" wide //weight: 1
        $x_1_10 = "Network\\Cookies" wide //weight: 1
        $x_1_11 = "dp.txt" wide //weight: 1
        $x_1_12 = "45.9.74.78" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RH_2147848410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RH!MTB"
        threat_id = "2147848410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 00 42 2e 69 6d 70 6f 72 74 73 00 10 00 00 00 10 06 00 00 10 00 00 00 10 06 00 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 60}  //weight: 1, accuracy: High
        $x_2_2 = {50 45 00 00 4c 01 05 00 fe 3b 2b 68 00 00 00 00 00 00 00 00 e0 00 03 01 0b 01 0e 00 00 de 04 00 00 92 00 00 00 00 00 00 40 77 02 00 00 10}  //weight: 2, accuracy: High
        $x_5_3 = {55 89 e5 53 57 56 81 ec 24 08 00 00 8b 4d 08 8d 05 44 23 ?? ?? 89 85 d4 fa ff ff 0f b7 01 89 85 08 fe ff ff 8a 8d b8 fe ff ff 88 8d b4 fe ff ff c6 45 c4 8d c6 45 c5 9b c6 45 c6 42 c6 45 c7 43 31 c9 83 f9 04 73 4c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RH_2147848410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RH!MTB"
        threat_id = "2147848410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "localappdata%\\Chro576xedmium" wide //weight: 1
        $x_1_2 = "appd576xedata%\\Ethe576xedreum" wide //weight: 1
        $x_1_3 = "Wallets/Exodus" wide //weight: 1
        $x_1_4 = "localappdata%\\Coinomi\\Coinomi\\wallets" wide //weight: 1
        $x_1_5 = "Wallets/Bitcoin core" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CRIT_2147849271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CRIT!MTB"
        threat_id = "2147849271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "os_c576xedrypt.encry576xedpted_key" ascii //weight: 1
        $x_1_2 = "Lum576xedmaC2, Build 20233101" ascii //weight: 1
        $x_1_3 = "LID(Lu576xedmma ID)" ascii //weight: 1
        $x_1_4 = "Phys576xedical Ins576xedtalled Memor576xedy:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPZ_2147852417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPZ!MTB"
        threat_id = "2147852417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f3 f6 17 8b c6 8b f3 33 db 33 f6 33 db 33 f6 8b f6 8b f3 33 f3 80 07 75 8b de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPZ_2147852417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPZ!MTB"
        threat_id = "2147852417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 89 45 f0 8b 4d e4 8b c6 d3 e8 89 45 f8 8b 45 dc 01 45 f8 8b 45 f8 33 45 f0 31 45 fc 8b 45 fc 29 45 e8 8b 45 d4 29 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPZ_2147852417_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPZ!MTB"
        threat_id = "2147852417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 16 5d 91 13 06 07 11 04 91 11 06 61 13 07 11 04 17 58 13 08 07 11 08 11 05 5d 91 13 09 20 00 01 00 00 13 0a 11 07 11 09 59 11 0a 58 11 0a 17 59 5f 13 0b 07 11 04 11 0b d2 9c 00 11 04 17 58 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RE_2147888161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RE!MTB"
        threat_id = "2147888161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 ca 83 e2 03 8a 54 14 08 32 54 0d 04 0f be d2 66 89 14 4f 41 39 c8 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCAK_2147889528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCAK!MTB"
        threat_id = "2147889528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 31 d2 f7 f7 0f b7 44 4d 00 66 33 04 53 66 89 44 4d 00 41 39 f1 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_EB_2147890360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EB!MTB"
        threat_id = "2147890360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-AppProvisionedPackage -online -packagepath" ascii //weight: 1
        $x_1_2 = "Remove-AppPackage -AllUsers -package" ascii //weight: 1
        $x_1_3 = "Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION" ascii //weight: 1
        $x_1_4 = "fyi/Blogtion.msi" ascii //weight: 1
        $x_1_5 = "ppCmdLine=/QN /norestart" ascii //weight: 1
        $x_1_6 = "DownloadFolder=[AppDataFolder]Dino" ascii //weight: 1
        $x_1_7 = "7AD83CDF-AB2B-4A72-A20E-2EDE7913C584" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NLS_2147891170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NLS!MTB"
        threat_id = "2147891170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 91 6c 01 00 00 89 54 24 04 e8 48 04 03 00 0f b6 44 24 ?? 84 c0 74 10 8b 44 24 10 c7 80 ?? ?? ?? ?? 00 00 00 00 eb 04 8b 44 24 10 8b 80 ?? ?? ?? ?? 89 44 24 1c 83 c4}  //weight: 5, accuracy: Low
        $x_1_2 = "atomic.QSY_zrh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCAZ_2147891191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCAZ!MTB"
        threat_id = "2147891191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 32 00 73 00 6f 00 63 00 6b}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 32 00 63 00 6f 00 6e 00 66}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 65 00 73 00 6c 00 61 00 42 00 72 00 6f 00 77 00 73 00 65 00 72}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2e 00 74 00 78 00 74}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 79 00 73 00 6d 00 6f 00 6e 00 44 00 72 00 76}  //weight: 1, accuracy: High
        $x_1_6 = {2a 00 2e 00 65 00 6d 00 6c}  //weight: 1, accuracy: High
        $x_1_7 = "- Screen Resoluton:" ascii //weight: 1
        $x_1_8 = "lid=%s&ver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SG_2147892484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SG!MSR"
        threat_id = "2147892484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TEXTBIN.NET/raw" ascii //weight: 1
        $x_1_2 = "VMware" ascii //weight: 1
        $x_1_3 = "processhacker" ascii //weight: 1
        $x_1_4 = "ollydbg" ascii //weight: 1
        $x_1_5 = "cuckoo" ascii //weight: 1
        $x_1_6 = "netmon" ascii //weight: 1
        $x_1_7 = "/VERYSILENT /SP-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCP_2147893005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCP!MTB"
        threat_id = "2147893005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 17 8b 3c 24 6b da ?? 8d bc 3b ?? ?? ?? ?? 89 3c 24 31 d0 89 c2 0f af 14 24 6b d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCT_2147893361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCT!MTB"
        threat_id = "2147893361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 8b 45 0c 30 54 07 ?? 8b 45 ?? 8b 10 8b 45 ?? 31 10 8b 54 9e ?? 8b 45 ?? 03 d1 31 10 3b 7d ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCV_2147893926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCV!MTB"
        threat_id = "2147893926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 3c 32 0f b6 db 31 fb 33 04 9d ?? ?? ?? ?? 46 89 c3 39 f1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_EM_2147894034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EM!MTB"
        threat_id = "2147894034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {d3 e7 01 f8 8d 4e ff 42 83 fe 01 89 ce 77 d5}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_EM_2147894034_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EM!MTB"
        threat_id = "2147894034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 ba}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCX_2147894037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCX!MTB"
        threat_id = "2147894037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 33 d8 8b c3 33 f3 33 c0 8b f0 8b c6 33 c6 8b d8 8b f6 80 07 ?? 8b c0 8b f6 8b db 33 d8 8b f0 8b f3 33 de 33 c6 8b f0 80 2f ?? 33 c3 8b f3 33 c6 8b f0 33 c6 33 d8 8b c0 8b f3 33 c6 f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCCZ_2147894254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCCZ!MTB"
        threat_id = "2147894254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f0 8b c3 33 c0 33 db 8b f6 8b db 8b d8 8b c3 f6 2f 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MA_2147895164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MA!MTB"
        threat_id = "2147895164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 dc 8b 00 89 45 d0 83 45 dc 04 8b 45 d4 89 45 d8 8b 45 d8 83 e8 04 89 45 d8 33 c0 89 45 ec 33 c0 89 45 b4 33 c0 89 45 b0 8b 45 e0 8b 10}  //weight: 5, accuracy: High
        $x_5_2 = {2b d8 81 c3 ?? ?? ?? ?? 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MB_2147895250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MB!MTB"
        threat_id = "2147895250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 4c 3c 14 0f b6 44 3e 02 c1 e0 10 09 c8 89 44 3c 14 0f b6 4c 3e 03 c1 e1 18 09 c1 89 4c 3c 14 83 c7 04}  //weight: 5, accuracy: High
        $x_5_2 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MC_2147896896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MC!MTB"
        threat_id = "2147896896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 85 fc eb ff ff 89 4d 10 2b f0 8d 85 f8 eb ff ff 6a 00 50 56 8d 85 fc eb ff ff 50 57 ff 15}  //weight: 5, accuracy: High
        $x_2_2 = ".vuia3" ascii //weight: 2
        $x_2_3 = "_GetPhysicalSize@12" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MD_2147896897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MD!MTB"
        threat_id = "2147896897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {22 eb f5 44 22 74 06 75 04 94 16 31 99 c7 44 24 fc 30 00 00 00 83 ec 04 75}  //weight: 2, accuracy: High
        $x_2_2 = {3d 3f d5 0e 82 43 c3 18 ea 3f c8 01 d2 2a b2 2a 72 03 cd 39 43 4c 36 28 6b b9 af 45 6c f1 cd 3f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ME_2147897140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ME!MTB"
        threat_id = "2147897140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c1 f6 d1 80 c9 61 00 c8 04 9f 20 c8 f6 d0 a2}  //weight: 1, accuracy: High
        $x_1_2 = {89 c1 83 c1 01 89 0f 0f b6 00 8b 55 ec 8b 0a 8b 75 f0 89 04 8e 8b 07 89 c1 83 c1 01 89 0f 0f b6 00 c1 e0 08 8b 0a 8b 14 8e 89 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MF_2147897141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MF!MTB"
        threat_id = "2147897141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 04 2d ?? ?? ?? ?? 01 47 68 a1 ?? ?? ?? ?? 8b 48 3c 8b 47 54 83 c1 ?? 03 c1 8b 8f a4 00 00 00 0f af 87 a0 00 00 00 89 87 a0 00 00 00 a1 ?? ?? ?? ?? 88 1c 08 ff 05 ?? ?? ?? ?? 81 fd ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MG_2147898259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MG!MTB"
        threat_id = "2147898259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 34 01 4c 24 14 8b f3 c1 ee 05 8d 3c 2b 83 f8 1b 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCEX_2147898444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCEX!MTB"
        threat_id = "2147898444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 2c 3e 6a 6a}  //weight: 1, accuracy: High
        $x_1_2 = {80 34 3e 8b 6a}  //weight: 1, accuracy: High
        $x_1_3 = {80 34 3e 85 6a}  //weight: 1, accuracy: High
        $x_1_4 = {80 04 3e b1 6a}  //weight: 1, accuracy: High
        $x_1_5 = {80 34 3e f1 6a}  //weight: 1, accuracy: High
        $x_1_6 = {80 04 3e 4b 6a}  //weight: 1, accuracy: High
        $x_1_7 = {80 04 3e ad 6a}  //weight: 1, accuracy: High
        $x_1_8 = {80 34 3e a8 6a}  //weight: 1, accuracy: High
        $x_1_9 = {80 04 3e f8 6a}  //weight: 1, accuracy: High
        $x_1_10 = {80 04 3e 6f 46 3b 74 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFE_2147898762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFE!MTB"
        threat_id = "2147898762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 24 8b 4c 24 ?? 0f b6 04 08 8b 4c 24 ?? 83 e1 1f 0f b6 4c 0c ?? 31 c8 8b 4c 24 0c 8b 54 24 ?? 88 04 11 8b 44 24 ?? 83 c0 01 89 44 24 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MH_2147898881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MH!MTB"
        threat_id = "2147898881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 33 c6 89 44 24 10 8b 44 24 18 31 44 24 10 2b 7c 24 10 81 c5 ?? ?? ?? ?? ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MI_2147899083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MI!MTB"
        threat_id = "2147899083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 89 44 24 10 8b 44 24 1c 31 44 24 10 2b 5c 24 10 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 34 01 44 24 18 2b 7c 24 18 ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NL_2147899512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NL!MTB"
        threat_id = "2147899512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {76 02 8b e9 33 c0 33 ff 3b eb 74 2e}  //weight: 3, accuracy: High
        $x_3_2 = {e8 36 fa ff ff 83 c4 ?? 80 7e 48 00 75 10 85 c0 78 0c 8b 4c 24 14 88}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NL_2147899512_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NL!MTB"
        threat_id = "2147899512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7c 16 43 33 f6 8b 47 ?? 8b d6 e8 e3 08 fc ff e8 26 fd fa ff 46 4b 75 ed}  //weight: 5, accuracy: Low
        $x_1_2 = "DiedHistoric" ascii //weight: 1
        $x_1_3 = "Andrews Signed Symposium Cart Nation Euros" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NL_2147899512_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NL!MTB"
        threat_id = "2147899512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 24 ?? 8a 4c 24 ?? 84 88 e1 8d ce 00 75 1e 83 7c 24 ?? 00 e9 fa 18 00 00 7f 72 00 0f b7 04 41 23 44 24 ?? eb 02 33 c0 85 c0 75 01}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 0e 89 48 0c 8b 4d ?? 89 48 04 8b 4d ?? 89 48 08 8b 0d 50 dc c4 00 47 89 58 18 89 48 1c 3b 7d ?? a3 50 dc c4 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NL_2147899512_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NL!MTB"
        threat_id = "2147899512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 13 8d 05 a0 3a 14 03 89 10 89 42 18 e8 55 14 00 00 fc e8 6f b9 fd ff 8b 44 24 78 89 04 24 8b 44 24 7c 89 44 24 04}  //weight: 3, accuracy: High
        $x_2_2 = {8b 7c 24 04 8b 15 b4 3a 18 03 64 8b 12 8b 02 8b 1c 24 89 58 20 8d 5c 24}  //weight: 2, accuracy: High
        $x_1_3 = "payloadType" ascii //weight: 1
        $x_1_4 = "LAUNCH_STAGE_UNSPECIFIED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFS_2147899685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFS!MTB"
        threat_id = "2147899685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce f7 e6 c1 ea ?? 6b c2 ?? 2b c8 8a 81 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MJ_2147899799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MJ!MTB"
        threat_id = "2147899799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 14 8b 44 24 10 c1 e9 05 03 4c 24 30 81 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFX_2147899807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFX!MTB"
        threat_id = "2147899807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fe 0f be 44 14 ?? 31 c1 0f be c1 8b 4c 24 ?? 8b 54 24 ?? 66 89 04 51 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "LummaC2" ascii //weight: 1
        $x_1_3 = "lummanowork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCFZ_2147900035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCFZ!MTB"
        threat_id = "2147900035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 83 e9 01 89 4d f4 8b 55 fc 33 55 f4 89 95 ?? ?? ?? ?? 8b 45 f4 83 e8 01 89 45 f4 83 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPY_2147900691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPY!MTB"
        threat_id = "2147900691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d b4 8b f0 6a 00 8d 45 a0 c7 45 a0 00 00 00 00 50 8b 11 6a 01 51 ff 52 0c 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPY_2147900691_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPY!MTB"
        threat_id = "2147900691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 46 78 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 46 70 89 c4 50 83 ec 0c 89 e0 83 e0 f0 89 46 7c 89 c4 50 83 ec 1c 89 e0 83 e0 f0 89 86 80 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCGW_2147900941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCGW!MTB"
        threat_id = "2147900941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d1 41 ff e1 31 c9 3d ?? ?? ?? ?? 0f 9c c1 8b 0c 8d ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 d1 41 ff e1 31 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHB_2147901239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHB!MTB"
        threat_id = "2147901239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 53 57 56 83 ec ?? 8b 4c 24 ?? a1 ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 d0 40 66 90 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHC_2147901336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHC!MTB"
        threat_id = "2147901336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 50 6a 00 53 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {50 ff 75 f8 ff 75 b0 57 53 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MK_2147901715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MK!MTB"
        threat_id = "2147901715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f0 8b f3 f6 2f 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHF_2147901759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHF!MTB"
        threat_id = "2147901759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 f1 8b 45 ?? 46 8a 0c 02 8b 55 ?? 32 0c 3a 88 0f 8b 7d ?? 3b f3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ML_2147902060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ML!MTB"
        threat_id = "2147902060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 f0 c7 45 [0-5] 83 45 f4 03 8b 45 ec c1 e0 04 83 3d [0-4] 0c 89 45 fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_A_2147902077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.A!MTB"
        threat_id = "2147902077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 07 25 80 2f ?? 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NLA_2147902335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NLA!MTB"
        threat_id = "2147902335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 d5 f6 c2 01 8b 7c 24 ?? 74 20 89 c2 81 f2 fe ff ff 3f}  //weight: 3, accuracy: Low
        $x_3_2 = {c9 89 8c 84 ?? ?? ?? ?? 83 bc 24 c8 15 00 00 ?? 0f 8e c0 00 00 00 31 c0 8b 4c 24 ?? 8d 0c c9 89 ca}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NSE_2147902408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NSE!MTB"
        threat_id = "2147902408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6b d2 28 8b 85 5c ff ff ff 8b 4c 10 ?? 89 8d e4 fe ff ff 8b 95 ?? ?? ?? ?? 81 e2 00 00 00 40 74 27}  //weight: 3, accuracy: Low
        $x_3_2 = {eb 0f 8b 95 ?? ?? ?? ?? 83 c2 01 89 95 ?? ?? ?? ?? 8b 85 68 ff ff ff 0f b7 48 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PADL_2147902484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PADL!MTB"
        threat_id = "2147902484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 c7 04 24 f0 43 03 00 83 04 24 0d a1 78 07 47 00 0f af 04 24 05 c3 9e 26 00 a3 78 07 47 00 0f b7 05 7a 07 47 00 25 ff 7f 00 00 59 c3}  //weight: 1, accuracy: High
        $x_1_2 = {30 04 1e 46 3b f7 7c e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NLE_2147902617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NLE!MTB"
        threat_id = "2147902617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Guardrails Aloin Cogent" ascii //weight: 2
        $x_2_2 = "Signor Shereefs Mossgrown" ascii //weight: 2
        $x_2_3 = "List Controller Setup" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_B_2147902821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.B!MTB"
        threat_id = "2147902821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c0 8b 04 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40}  //weight: 2, accuracy: Low
        $x_1_2 = "Windows 10" ascii //weight: 1
        $x_1_3 = "Windows 11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCHX_2147905293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCHX!MTB"
        threat_id = "2147905293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 04 31 83 ff 0f 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SPD_2147905681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SPD!MTB"
        threat_id = "2147905681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 ec 31 45 e8 8b 45 f4 33 45 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MAC_2147906485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MAC!MTB"
        threat_id = "2147906485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 bc 50 44 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 bc 50 44 00 8a 0d be 50 44 00 30 0c 33 83 ff 0f 75 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NM_2147907640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NM!MTB"
        threat_id = "2147907640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 35 08 91 75 00 8d 4f ?? 03 74 24 18 ba ?? ?? ?? ?? 8b 5e 04 2b f7}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 04 0e 8d 49 ?? 03 c3 89 41 fc 83 ea 01 75 f0 a1 0c 91 75 00 89 47 08 8d 44 24 10}  //weight: 3, accuracy: Low
        $x_1_3 = "GameJack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_JHU_2147907724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.JHU!MTB"
        threat_id = "2147907724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 4c 24 10 8b 54 24 14 88 44 3c 18 88 5c 2c ?? 0f b6 44 3c ?? 03 c6 0f b6 c0 0f b6 44 04 ?? 30 04 0a 41 89 4c 24 10 3b 8c 24 24 02 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_TTB_2147907887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.TTB!MTB"
        threat_id = "2147907887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 8b 15 ?? ?? ?? ?? 8b 44 24 0c 69 d2 fd 43 03 00 81 c2 c3 9e 26 00 89 15 14 ea 44 00 8a 0d ?? ?? 44 00 30 0c 30 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NME_2147908252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NME!MTB"
        threat_id = "2147908252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {32 37 3e 34 ?? 83 c4 04 5b 69 8d ?? ?? ?? ?? fe 00 00 00 81 c1 3b 66 f3 56 69 95 ?? ?? ?? ?? fe 00 00 00}  //weight: 3, accuracy: Low
        $x_3_2 = {49 4c 39 4f ?? 3e 4c 39 37 45 83 c4 ?? 5b 8b 8d 84 fd ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RO_2147909020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RO!MTB"
        threat_id = "2147909020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 14 24 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 14 04 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 1c 00 00 00 00 89 4c 24 20 89 44 24 24 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {89 14 24 89 4c 24 04 89 44 24 08 c7 44 24 0c 00 30 00 00 c7 44 24 10 40 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_C_2147909823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.C!MTB"
        threat_id = "2147909823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 c8 01 c0 89 c1 31 d1 f7 d0 21 d0 01 c0 29 c8 89 c1 83 c9 ?? 83 e0 ?? 01 c8 fe c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIF_2147909879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIF!MTB"
        threat_id = "2147909879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 c8 01 c0 89 c1 31 d1 f7 d0 21 d0 01 c0 29 c8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIG_2147912936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIG!MTB"
        threat_id = "2147912936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 28 8b 6c 24 ?? a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 90 90 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIH_2147912937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIH!MTB"
        threat_id = "2147912937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 95 c2 8b 04 95 ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 c2 42 31 c0 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MVV_2147912963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MVV!MTB"
        threat_id = "2147912963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8b 4c 24 18 03 c6 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24 28 02 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MWW_2147912992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MWW!MTB"
        threat_id = "2147912992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d9 80 e1 10 d3 e5 89 fa 83 e2 fc 33 6c 14 1c 89 6c 14 ?? 0f b6 74 38 01 80 c9 08 d3 e6 31 ee 89 74 14 ?? 83 c7 02 83 c3 10 39 3c 24 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MML_2147913229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MML!MTB"
        threat_id = "2147913229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 03 c3 2e 82 a7 a7 a7 a7 4c 96 8d 05 02 20 40 00 80 30 a7 40 3d 34 20 40 00 75 ?? 05 54 82 37 1c 29 c0 29 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YR_2147913412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YR!MTB"
        threat_id = "2147913412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 c0 29 c0 0f c8 8d 05 00 20 40 00 83 c0 02 50 11 c0 8d 80 42 44 23 0b 58 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIQ_2147913508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIQ!MTB"
        threat_id = "2147913508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 07 cb 65 fa 63 c7 47 ?? e5 61 f0 6f c7 47 ?? f2 6d b1 6b c7 47 ?? b4 69 ba 57 c7 47 ?? fa 55 c0 53 c7 47 ?? c6 51 50 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RON_2147913979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RON!MTB"
        threat_id = "2147913979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 b5 f8 fb ff ff e8 ?? ?? ?? ?? 8a 85 f8 fb ff ff 30 04 3b 83 7d 08 0f 59 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RRC_2147914137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RRC!MTB"
        threat_id = "2147914137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 24 8b 4c 24 3c 8b 74 24 30 03 0a 0f b6 06 30 01 8b c2 8b 4c 24 ?? 2b ca 83 e1 fc 81 f9 00 10 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIY_2147914469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIY!MTB"
        threat_id = "2147914469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 02 8b 8d ?? f8 ff ff 8b 11 83 c2 01 33 c2 8b 8d ?? f8 ff ff c1 e1 00 03 8d ?? f8 ff ff 88 01 eb ?? 8b 95 ?? f8 ff ff 8b 02 83 c0 02 8b 8d ?? f8 ff ff 39 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCIZ_2147915033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCIZ!MTB"
        threat_id = "2147915033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 57 56 83 e4 ?? 83 ec ?? 89 e6 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GZX_2147915673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GZX!MTB"
        threat_id = "2147915673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 d1 c1 e9 06 80 c1 c0 88 4d 00 80 e2 3f 80 ca 80 88 55 01}  //weight: 5, accuracy: High
        $x_5_2 = {83 cb 0a 0f af 5c 24 0c 83 74 24 0c 0a 8b 7c 24 04 83 e7 f5 0f af 7c 24 0c 89 7c 24 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCJB_2147915675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCJB!MTB"
        threat_id = "2147915675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 14 10 81 c1 ?? ?? ?? ?? 31 d1 89 4c 24 08 8b 4c 24 08 89 ca 83 ca 45 83 e1 45 01 d1 fe c1 8b 54 24 04 88 4c 14 10 ff 44 24 04 8b 4c 24 04 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BBA_2147915703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BBA!MTB"
        threat_id = "2147915703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 ac 2c 65 34 22 2c 73 68 ?? ?? ?? ?? 88 04 37 e8 22 6d fe ff 30 04 37 83 c4 1c 46 3b 75 18 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PH_2147915993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PH!MTB"
        threat_id = "2147915993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 8b 14 98 8b 44 24 ?? 8b 48 08 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PH_2147915993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PH!MTB"
        threat_id = "2147915993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 c0 8b 04 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40}  //weight: 3, accuracy: Low
        $x_1_2 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 5d 00 53 e8 ?? ?? ?? ?? 83 c4 04 85 c0 74 ?? 45 90 90 90 90 90 90}  //weight: 1, accuracy: Low
        $x_3_4 = {0f b6 d2 c1 e1 05 81 e1 e0 7f 00 00 31 d1 0f b7 94 4e 72 92 02 00 89 c7 81 e7 ff 7f 00 00 66 89 94 7e 72 92 01 00 89 da 42 66 89 84 4e 72 92 02 00 45}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_QTW_2147916525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.QTW!MTB"
        threat_id = "2147916525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 b0 8b 44 24 24 81 c2 ?? ?? ?? ?? 8b 4c b0 04 8b 44 24 3c 8a 04 01 8d 4c 24 24 30 02 e8 ?? ?? ?? ?? 8d 4c 24 48 e8 ?? ?? ?? ?? 8d 4c 24 30 e8 ?? ?? ?? ?? 8d 4c 24 3c e8 ?? ?? ?? ?? 8b 44 24 18 47 89 7c 24 14 81 ff 00 2c 12 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AMAX_2147917143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMAX!MTB"
        threat_id = "2147917143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c b8 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 [0-5] e8 ?? ?? ?? ?? 8d 4c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AFZ_2147917295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AFZ!MTB"
        threat_id = "2147917295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 01 30 04 37 8b 44 24 18 2b c1 83 e0 fc 50 51 e8 ?? ?? ?? ?? 46 89 5c 24 18 59 59 89 5c 24 14 89 5c 24 18 3b 74 24 30 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DA_2147917488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DA!MTB"
        threat_id = "2147917488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "<HTA:APPLICATION icon=\"#\" WINDOWSTATE=\"normal\" SHOWINTASKBAR=\"no\" SYSMENU=\"no\" CAPTION=\"no\" BORDER=\"none\" SCROLL=\"no\"" ascii //weight: 20
        $x_20_2 = "<HTA:APPLICATION CAPTION = \"no\" WINDOWSTATE = \"minimize\" SHOWINTASKBAR = \"no\"" ascii //weight: 20
        $x_1_3 = "window.close();" ascii //weight: 1
        $x_1_4 = {65 00 76 00 61 00 6c 00 28 00 [0-15] 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {65 76 61 6c 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_6 = "</script>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_AMAC_2147918784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMAC!MTB"
        threat_id = "2147918784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 fe 81 ef [0-4] 2b f8 31 3b 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 c3 8b 45 ec 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AMAE_2147919161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMAE!MTB"
        threat_id = "2147919161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f8 31 3b 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 c3 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MNZ_2147919283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MNZ!MTB"
        threat_id = "2147919283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 da 83 e2 1e 0f b6 54 14 0c 32 54 1d 20 88 54 1d 00 8d 53 01 83 e2 1f 0f b6 54 14 0c 32 54 1d 21 88 54 1d 01 83 c3 02 39 d9 75 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MFF_2147919627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MFF!MTB"
        threat_id = "2147919627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {ba 48 00 00 00 29 c2 05 b7 25 94 b0 31 c2 21 ca 31 c2 89 54 24 04 8b 44 24 04 fe c8 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8 20 72 c7}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NT_2147920275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NT!MTB"
        threat_id = "2147920275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 0c 00 00 00 00 c6 44 24 10 00 c7 44 24 14 04 00 00 08 c7 44 24 18 00 00 00 00 c7 44 24 1c 00 00 00 00 8d 94 24 20 01 00 00 89 54 24 20}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4c 24 28 89 4c 24 3c c7 04 24 00 00 00 00 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_TRI_2147920357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.TRI!MTB"
        threat_id = "2147920357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {29 c2 05 3a ac 7c c9 31 c2 21 ca 31 c2 89 54 24 0c 8b 44 24 0c 04 6a 8b 4c 24 04 88 44 0c 38 ff 44 24 04 8b 44 24 04 83 f8 2d 72 c2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GPH_2147920500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GPH!MTB"
        threat_id = "2147920500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 0f 05 ?? ?? ?? ?? 31 c8 89 45 ?? 8b 45 ?? 04 ?? 8b 4d ?? 88 04 0f ff 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_XCA_2147920797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.XCA!MTB"
        threat_id = "2147920797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {31 d1 89 4d e4 8b 4d e4 80 c1 36 8b 55 ?? 88 0c 10 ff 45 ec 8b 4d ec 83 f9 16 72}  //weight: 4, accuracy: Low
        $x_5_2 = {31 fe 89 75 e8 8b 5d e8 80 c3 d6 8b 75 ?? 88 1c 30 ff 45 f0 8b 75 f0 83 fe 06 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_VG_2147921119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.VG!MTB"
        threat_id = "2147921119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f3 a5 8b 74 24 f8 8b 7c 24 f4 8d 54 24 04 ff 54 24 fc c3}  //weight: 2, accuracy: High
        $x_1_2 = "Qkkbal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AQ_2147921655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AQ!MTB"
        threat_id = "2147921655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 04 24 8b 0c 24 0f b6 4c 0c 08 05 ?? ?? ?? ?? 31 c8 89 44 24 04 8b 44 24 04 04 ?? 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8 08 72}  //weight: 4, accuracy: Low
        $x_1_2 = {81 3c ca 13 f2 8e 14 74 07 41 39 c8 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ALU_2147921664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ALU!MTB"
        threat_id = "2147921664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c2 cf 66 de 19 89 d6 21 ce 89 d3 31 cb f7 d1 09 ca 29 d1 01 f1 8d 0c 4b 89 4d ec 8b 4d ec 80 c1 f5 8b 55 f0 88 4c 15 d0 ff 45 f0 8b 4d f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MIP_2147921736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MIP!MTB"
        threat_id = "2147921736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 0c 24 8b 14 24 0f b6 54 14 28 81 c1 92 ea fe 52 31 d1 89 4c 24 ?? 8b 4c 24 ?? 80 c1 26 8b 14 24 88 4c 14 ?? ff 04 24 8b 0c 24 83 f9 67 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RP_2147921834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RP!MTB"
        threat_id = "2147921834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.UlhMFyDdoz" ascii //weight: 1
        $x_1_2 = "main.AEKCihaLRV" ascii //weight: 1
        $x_10_3 = "main.uydiOYgQCH.deferwrap2" ascii //weight: 10
        $x_10_4 = "main.uydiOYgQCH.deferwrap1" ascii //weight: 10
        $x_10_5 = "main.mOaSjsgDny.func1.Print.1" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCJR_2147922167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCJR!MTB"
        threat_id = "2147922167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 04 24 0f b6 44 ?? 04 ff 34 24 50 e8 ?? ?? ?? ?? 83 c4 08 8b 0c 24 88 44 0c 04 ff ?? 24 8b 04 24 83 f8}  //weight: 5, accuracy: Low
        $x_6_2 = {21 d1 f7 d1 01 c8 8b 0c 24 8b 54 24 ?? 89 ce f7 d6 09 d6 01 f1 29 c8}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_EC_2147922744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EC!MTB"
        threat_id = "2147922744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.opWGippTfg.deferwrap2" ascii //weight: 1
        $x_1_2 = "main.opWGippTfg.deferwrap1" ascii //weight: 1
        $x_1_3 = "main.KqqAVmjanJ" ascii //weight: 1
        $x_1_4 = "main.fQyfTGPUtq" ascii //weight: 1
        $x_1_5 = "exithook/hooks.go" ascii //weight: 1
        $x_1_6 = "go-telegram-bot-api" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DMP_2147923015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DMP!MTB"
        threat_id = "2147923015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c3 89 de 83 e6 01 89 f1 f7 d9 81 f6 01 01 01 01 89 df 81 e7 fe 00 00 00 0f af fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCJS_2147923062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCJS!MTB"
        threat_id = "2147923062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 08 0f b6 44 04 28 ff 74 24 08 50 e8 ?? ?? ?? ?? 83 c4 08 8b 4c 24 08 88 44 0c 28 ff 44 24 08 8b 44 24 08 83 f8}  //weight: 5, accuracy: Low
        $x_6_2 = {89 44 24 08 8b 44 24 14 05 ?? ?? ?? ?? 89 44 24 04 8b 44 24 08 33 44 24 04 89 04 24}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BKC_2147923086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BKC!MTB"
        threat_id = "2147923086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 f6 ff 0f af f5 89 d3 21 fb 09 fa 0f af d3 01 f2 03 14 24 8a 1c 15 ?? ?? ?? ?? 89 c6 83 c6 ff 88 58 ff 8a 14 15 ?? ?? ?? ?? 83 c6 ff 88 50 fe c1 e9 08 89 f0 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DDI_2147923326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DDI!MTB"
        threat_id = "2147923326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {80 c1 33 32 0c 1a fe c1 88 0c 1a 43 83 fb 14}  //weight: 5, accuracy: High
        $x_4_2 = {89 d7 31 c7 21 d0 81 f7 c2 00 00 00 8d 04 47 32 84 16 ?? ?? ?? ?? 04 36 88 84 16 ?? ?? ?? ?? 42 83 c1 02 83 fa 15 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CZ_2147923538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CZ!MTB"
        threat_id = "2147923538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c2 f7 d2 21 ca f7 d1 21 c8 29 d0 89 44 24 08 8b 44 24 08 05 35 2e 1f fe 89 c1 83 e1 01 d1 e1 83 f0 01 01 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YAC_2147923870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YAC!MTB"
        threat_id = "2147923870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5f 50 81 e0 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 81 f0 ?? ?? ?? ?? 58 0f b6 8d}  //weight: 10, accuracy: Low
        $x_1_2 = {58 0f b6 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f be 02 2b c1 8b 8d ?? ?? ?? ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YAC_2147923870_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YAC!MTB"
        threat_id = "2147923870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 9c c0 8b 04 85 ?? ?? ?? ?? b9 42 7c b1 d1 33 0d ?? ?? ?? ?? 01 c8 40 ff e0}  //weight: 10, accuracy: Low
        $x_1_2 = {89 ce 21 de 01 f6 29 de 01 d6 21 ce 89 f5 81 e5 ?? ?? ?? ?? 89 f0 83 e0 02 89 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YAD_2147923871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YAD!MTB"
        threat_id = "2147923871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {8b 44 24 14 2d ?? ?? ?? ?? 89 44 24 04 8b 44 24 08 33 44 24 04 89 04 24 8b 04 24 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 2d ?? ?? ?? ?? 83 c0 01 0f b6 c0}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPA_2147924468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPA!MTB"
        threat_id = "2147924468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "124"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 65 66 65 72 77 72 61 70 32}  //weight: 10, accuracy: Low
        $x_1_2 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 65 66 65 72 77 72 61 70 31}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 32}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 33}  //weight: 1, accuracy: Low
        $x_10_6 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 34}  //weight: 10, accuracy: Low
        $x_100_7 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31 2e 50 72 69 6e 74 2e 31}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NG_2147924508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NG!MTB"
        threat_id = "2147924508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c4 08 a3 1c 85 44 00 68 6c d4 6c e5 ff 35 14 85 44 00 e8 ?? ?? ?? ?? 83 c4 08 a3 20 85 44 00 68 5c 40 7d ec ff 35 14 85 44 00}  //weight: 3, accuracy: Low
        $x_2_2 = {a3 e8 74 44 00 ff 35 14 85 44 00 e8 ?? ?? ?? ?? 83 c4 04 0f b6 c0 8b 04 85 d0 52 44 00 b9 a4 bb 8b ae 33 0d d8 52 44 00 01 c1 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YAI_2147924779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YAI!MTB"
        threat_id = "2147924779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {c1 ea 04 8d 04 ?? c1 e0 ?? 29 c7 0f b6 44 3c ?? 32 81 40 65 0c 10 8b 54 24 ?? 88 04 0a 83 c1 01 39 4c 24}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ALM_2147924858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ALM!MTB"
        threat_id = "2147924858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 d3 80 c3 60 32 1c 14 80 c3 20 88 1c 14 42 83 fa 04}  //weight: 3, accuracy: High
        $x_2_2 = {89 d3 80 c3 9d 32 1c 10 80 c3 ef 88 1c 10 42 81 0e 04 eb 7a e0 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPE_2147924996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPE!MTB"
        threat_id = "2147924996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 e0 01 00 00 00 90 06 00 00 02 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f0 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 80 05 00 00 10 00 00 00 7e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 90 05 00 00 00 00 00 00 8e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 05 00 00 02 00 00 00 8e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_3 = {20 20 20 00 20 20 20 20 00 d0 05 00 00 10 00 00 00 5e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 e0 05 00 00 00 00 00 00 6e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 f0 05 00 00 02 00 00 00 6e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_4 = {20 20 20 00 20 20 20 20 00 80 05 00 00 10 00 00 00 80 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 40 03 00 00 00 90 05 00 00 04 00 00 00 90 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 05 00 00 02 00 00 00 94 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_RPB_2147925007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPB!MTB"
        threat_id = "2147925007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 65 66 65 72 77 72 61 70 31}  //weight: 1, accuracy: Low
        $x_100_3 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31 2e 50 72 69 6e 74 2e 31}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPC_2147925008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPC!MTB"
        threat_id = "2147925008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31}  //weight: 1, accuracy: Low
        $x_100_2 = {6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 31 2e 50 72 69 6e 74 2e 66 75 6e 63 31}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ALR_2147925240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ALR!MTB"
        threat_id = "2147925240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 da 88 f8 08 ef 80 e5 1f 24 1f 08 ec f6 d7 08 c1 30 cc 08 e7 8a 64 24 03 88 e0 20 f0 30 e6 08 c6 88 f8 f6 d0 20 f0 f6 d6 20 fe 08 c6 89 d0 80 e2 40 f6 d0 24 bf 08 c2 88 f0 80 f2 40 20 d0 30 f2 08 c2 b8 31 d4 6a ea 88 14 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_WND_2147925327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.WND!MTB"
        threat_id = "2147925327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 d8 04 61 32 04 19 04 1b 88 04 19 43 83 fb 13 75 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ALE_2147925568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ALE!MTB"
        threat_id = "2147925568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c7 83 e7 0d 89 c3 83 e3 02 89 de 83 f6 02 0f af f7 83 cf 02 0f af fb 89 c5 81 cd 50 65 c5 1d 89 cb 81 cb af 9a 3a e2 21 eb f7 d3 01 f3 01 fb 89 de 21 d6 01 d3 01 f6 29 f3 80 c3 95 88 5c 04 0c 40 49 83 f8 1b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MEL_2147925577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MEL!MTB"
        threat_id = "2147925577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c9 8b 85 e0 ef ff ff 30 0c 10 8b 95 ec ef ff ff 83 c7 04 42}  //weight: 2, accuracy: High
        $x_1_2 = "database\\wirefr\\x64\\HTTP\\Intero.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NDO_2147925603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NDO!MTB"
        threat_id = "2147925603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 cb 20 c2 08 d3 89 ca 30 c1 20 c2 08 d1 89 ca 30 da 84 c9}  //weight: 2, accuracy: High
        $x_1_2 = {89 d3 80 f3 01 88 df 89 d8 20 d7 08 f2 20 f8 30 df 80 f2 01 08 c7 88 f8 20 f7 80 f6 01 34 01 20 f0 30 de 08 f2 08}  //weight: 1, accuracy: High
        $x_1_3 = {bf bd ef a9 a8 31 e0 89 44 24 54 8d 46 04 89 74 24 10 89 74 24 14 89 44 24 0c 89 44 24 18 8b 44 24 14 8b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NDP_2147925769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NDP!MTB"
        threat_id = "2147925769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 85 e4 fd ff ff 83 c4 10 8b 4d fc 33 cd e8 1c 88 fe ff c9 c3 8b ff 55 8b ec 6a 04 6a 00 ff 75 08 6a 00}  //weight: 2, accuracy: High
        $x_1_2 = {30 ca 88 e8 30 cd 20 c8 88 d1 08 c5 f6 d1 88 e8 20 e9 08 d5 f6 d0 20 c2 88 e8 08 ca 30 d0 0f 45 f7 84 d2}  //weight: 1, accuracy: High
        $x_1_3 = {89 c8 89 ce f7 d0 81 f6 ce 0f 71 d9 89 c2 21 ce 81 e2 ce 0f 71 d9 89 d7 21 f7 31 d6 09 fe 89 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SLK_2147925844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SLK!MTB"
        threat_id = "2147925844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d1 83 f1 6a 01 f1 8b 75 ?? 29 f9 01 d1 32 0c 16 80 c1 ee 88 0c 16 42 83 fa 1c 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPF_2147925872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPF!MTB"
        threat_id = "2147925872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d8 04 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f2 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPF_2147925872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPF!MTB"
        threat_id = "2147925872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 74 65 78 74 00 00 00 00 30 0f 00 00 10 00 00 00 2c 0f 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 64 61 74 61 00 00 00 e0 00 00 00 40 0f 00 00 e0 00 00 00 32 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 00 50 00 00 00 20 10 00 00 26 00 00 00 12 10 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 30 30 63 66 67 00 00 00 20 00 00 00 70 10 00 00 02 00 00 00 38 10 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 72 65 6c 6f 63 00 00 40 49 00 00 00 90 10 00 00 4a 00 00 00 3a 10 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42 2e 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BSA_2147925893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BSA!MTB"
        threat_id = "2147925893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "fequal.exe" ascii //weight: 10
        $x_3_2 = {eb 10 66 62 3a 43 2b ?? ?? ?? ?? ?? ?? e9 ac b0 73 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BSA_2147925893_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BSA!MTB"
        threat_id = "2147925893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e4 8b 08 89 4d f4 8b 40 04 89 45 f8 8b 4d f4 8b 45 f8 31 d2 89 0c 24 89 44 24 04 c7 44 24 08 00 00 00 00 e8 c6 ?? ?? ?? 83 f8 00 0f 84 0c 00 00 00 c7 04 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BSA_2147925893_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BSA!MTB"
        threat_id = "2147925893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 70 2e 00 00 10 00 00 00 76 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 80 2e 00 00 00 00 00 00 86 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 90 2e 00 00 02 00 00 00 86 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BSA_2147925893_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BSA!MTB"
        threat_id = "2147925893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 60 05 00 00 10 00 00 00 5c 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 70 05 00 00 02 00 00 00 6c 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 80 05 00 00 02 00 00 00 6e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 90 24 00 00 10 00 00 00 62 01 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 a0 24 00 00 02 00 00 00 72 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 b0 24 00 00 02 00 00 00 74 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_RPG_2147925991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPG!MTB"
        threat_id = "2147925991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 72 62 00 73 69 68 78 75 69 41 73 75 69 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPH_2147925998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPH!MTB"
        threat_id = "2147925998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 ?? ?? 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 e0 01 00 00 00 90 06 00 00 02 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 b0 06 00 [0-240] 2e 74 61 67 67 61 6e 74 00 30 00 00 00 ?? ?? 00 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPI_2147926169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPI!MTB"
        threat_id = "2147926169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 20 05 00 00 10 00 00 00 20 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 30 05 00 00 00 00 00 00 30 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 40 05 00 00 02 00 00 00 30 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 90 24 00 00 10 00 00 00 62 01 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 a0 24 00 00 00 00 00 00 72 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 b0 24 00 00 02 00 00 00 72 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_3 = {20 20 20 00 20 20 20 20 00 80 05 00 00 10 00 00 00 80 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 40 03 00 00 00 90 05 00 00 04 00 00 00 90 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 05 00 00 02 00 00 00 94 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_4 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 48 04 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f2 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_5 = {20 20 20 00 20 20 20 20 00 50 05 00 00 10 00 00 00 5e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 60 05 00 00 00 00 00 00 6e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 70 05 00 00 02 00 00 00 6e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_NDR_2147926178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NDR!MTB"
        threat_id = "2147926178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 df 30 f9 34 ff 88 cd 30 c5 20 cd 88 f0 34 ff 24 01 8a 4d e3 80 f1 01 88 f3 20 cb 8a 7d e3 80 f7 01 80 e7 ff 80 e1 01 08 d8 08 cf 30 f8}  //weight: 2, accuracy: High
        $x_1_2 = {88 c2 80 f2 ff 80 e2 01 b4 01 88 e5 80 f5 01 88 c6 20 ee 08 f2 80 f2 ff 80 f2 01 80 e2 ff 88 e5 80 f5 01 80 e5 01 88 e6 80 f6 01 88 f3 80 e3 01 88 e7 80 f7 01 80 e7 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZZ_2147926185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZZ!MTB"
        threat_id = "2147926185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3}  //weight: 1, accuracy: High
        $x_1_2 = {b0 40 c3 b0 3f c3 80 f9 30 72 ?? 80 f9 39 77 06 80 c1 04 89 c8 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_TTV_2147926798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.TTV!MTB"
        threat_id = "2147926798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f6 e1 89 f1 00 c0 00 c3 89 c8 24 ?? 28 c3 0f b6 c3 01 d0 04 0b 32 04 17 04 c9 88 04 17 42 83 c1 ?? 83 fa 1b 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GQX_2147926996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GQX!MTB"
        threat_id = "2147926996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 f9 09 f0 09 cb 31 d8 89 d1 21 c1 31 c2 09 d1 89 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NDS_2147927077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NDS!MTB"
        threat_id = "2147927077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {59 eb 02 33 f6 33 db 56 e8 d6 db ff ff 59 8b c3 8d 65 ec 5f 5e 5b 8b 4d fc 33 cd e8}  //weight: 2, accuracy: High
        $x_1_2 = {75 ef 56 e8 a4 03 00 00 eb 06 56 e8 83 00 00 00 33 c0 59 8b 4d fc 5f 5e 33 cd 5b e8 f4 96 ff ff c9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NDS_2147927077_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NDS!MTB"
        threat_id = "2147927077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CZJvss--" ascii //weight: 2
        $x_1_2 = {f7 d5 21 eb 09 f3 f7 d0 21 c7 09 cf 89 dd 0f a4 fd 01 8d 34 3f f7 d5 f7 d6 01 fe 11 dd}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 c0 89 c6 f7 d6 0f b7 c9 21 ce f7 d1 21 c1 31 c0 39 ce 0f 94 c0 8b 4c 24 04}  //weight: 1, accuracy: High
        $x_1_4 = {31 d1 69 c9 93 01 00 01 0f be 50 01 31 ca 69 ca 93 01 00 01 0f be 50 02 31 ca 69 ca 93 01 00 01 0f be 50 03 83 c0 04 31 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NDT_2147927078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NDT!MTB"
        threat_id = "2147927078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {59 eb 02 33 f6 33 db 56 e8 36 c6 ff ff 59 8b c3 8d 65 ec 5f 5e 5b 8b 4d fc 33 cd e8 89 3f ff ff c9 c3}  //weight: 2, accuracy: High
        $x_2_2 = {59 59 33 c0 8d 65 cc 5f 5e 5b 8b 4d fc 33 cd e8 ce 15 ff ff c9 c3 33 c0 50 50 50}  //weight: 2, accuracy: High
        $x_1_3 = {eb 05 83 ca ff 8b c2 5f 5e 8b 4d fc 33 cd 5b e8 d1 b2 ff ff c9 c3 8b ff 55 8b ec 83 ec 24 53 56 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPJ_2147927298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPJ!MTB"
        threat_id = "2147927298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 e0 01 00 00 00 90 06 00 00 02 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f0 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 44 03 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f2 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 74 05 83 f8 2e 75 01}  //weight: 1, accuracy: High
        $x_1_2 = {3d 74 05 83 f9 2e 75 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 60 08 01 b3 85 d7 34 66 85 80 b5 4a a9 2b 43 09 2a d6 47 e5 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e6 09 f2 89 57 48 01 c8 89 47 44 83 f8 08 72 39 8b 74 24 08 eb 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 56 48 83 c0 f8 89 46 44 83 f8 07 76 42 8b 4e 30 3b 4e 34 73 e7 8d 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 77 28 73 25 56 ff 77 2c ff 77 20 ff 71 34 ff 51 30 83 c4 10 85 c0 0f 84 7c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7a 36 14 1b 4f b1 6b 6b 91 3c f8 0c ed 40 a6 38 f9 ef 8b 67 d6 8c b2 1b af 31 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 41 80 e5 29 41 80 e2 10 45 08 ea 45 08 df 41 80 e3 29 80 e1 d6 44 08 d9 44 30 d1 41 f6 d7 41 08 cf 89 d9 20 d1 30 da 08 ca 44 89 f9 f6 d1 20 d1 f6 d2 44 20 fa 08 ca 44 08 c8 f6 d0 89 d1 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 63 52 3c 4d 03 c2 4d 8b d0 4c 89 55 b8 4c 89 45 b0 45 33 c9 66 41 81 7a 18 0b 02 41 0f 94 c1 44 89 4d ac 45 85 c9 4d 8b d8 4d 0f 45 da 4c 89 5d a0 b9 60 00 00 00 89 4d 9c bb 18 00 00 00 48 63 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 1c 38 88 1c 39 0f b6 5c 38 ff 88 5c 39 ff 0f b6 5c 38 fe 88 5c 39 fe 0f b6 5c 38 fd 88 5c 39 fd 0f b6 5c 38 fc 88 5c 39 fc 0f b6 5c 38 fb 88 5c 39 fb 0f b6 5c 38 fa 88 5c 39 fa 0f b6 5c 38 f9 88 5c 39 f9 83 c7 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 20 f3 45 88 d3 41 20 fb 41 30 fa 45 08 d3 41 88 ea 41 80 f2 ff 40 88 df 40 80 f7 ff 41 88 f6 41 80 f6 01 45 88 d7 41 80 e7 ff 44 20 f5 41 88 fc 41 80 e4 ff 44 20 f3 41 08 ef 41 08 dc 45 30 e7 41 08 fa 41 80 f2 ff 41 80 ce 01 45 20 f2 45 08 d7 45 88 da 41 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 30 c7 40 88 f0 34 ff 45 88 f4 41 80 f4 ff 41 88 fd 41 80 f5 00 88 c1 80 e1 00 44 20 ee 44 88 e2 80 e2 00 45 20 ee 40 08 f1 44 08 f2 30 d1 44 08 e0 34 ff 41 80 cd 00 44 20 e8 08 c1 40 88 f8 34 00 44 88 fa 80 f2 ff 40 88 fe 40 80 f6 01 41 88 c6 41 80 e6 ff 41 88 f4 41 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c af c6 43 3d c1 c6 43 3e e0 c6 43 3f c7 c6 43 40 8c c6 43 41 c5 c6 43 42 ab c6 43 43 cb c6 43 44 a6 c6 43 45 c9 c6 43 46 a3 c6 43 47 cf c6 43 48 5b c6 43 49 cd c6 43 4a b0 c6 43 4b f3 c6 43 4c 9a c6 43 4d f1 c6 43 4e 61 c6 43 4f f7 c6 43 50 64 c6 43 51 f5 c6 43 52 9f c6 43 53 fb c6 43 54 65 c6 43 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 5c 51 3a 1d ab d9 02 2b 28 3b 82 87 c3 08 c6 2e f4 5a b9 27 fd 1e 8e 28 6f 1f f5 17 06 f3 44 2f 35 77 ca 2a 48 ef b6 05 d8 59 22 61 3e ed e6 12 8c 2b d8 77 29 90 12 ac 0f 49 1c 8b dc fd 84 e4 44 f7 08 0c 1b fb 25 5b cc 8b a6 59 d7 77 70 2f b7 1f 6e 5b a0 94 0a 72 4c 37 a5 71 24 a8 23 70 fb 9a cd 3c 1a 37 22 59 1b d8 42 0f f7 2a ca dd a6 e5 0f 8e a5 c5 a4 6c e6 ec 01 fa 0b 49 63 69 aa bd 85 f5 d8 83 5b bb 42 0e 6a 7a 0e d1 0d cc d9 94 85 7a 8a 89 7d 5f e9 b1 99 f9 41 0f 48 d8 5e 24 5c a9}  //weight: 1, accuracy: High
        $x_1_2 = {03 87 85 a2 e9 e5 c9 b6 13 5b 6c d0 2f da 86 22 fc 0b 5e 2a e7 1d 7c 1e bb 5c 5f 29 c3 46 3e 82 a3 6c 59 78 cf 57 91 5e 8a 76 33 db b7 7c df 50 d3 80 f6 4a 63 a7 d5 bf 7c 3a 78 b8 42 8c 21 83 61 9f e2 63 66 99 6e fb 5e b2 9e ac ca 96 42 f2 19 aa 79 07 7d d4 43 34 a1 1f 73 3f 82 d3 bd c9 93 34 ca a8 19 71 e0 ca a9 06 c0 5b 9b ae bb c1 69 f4 8a 1b ed 7c d6 01 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 51 92 9b 7b 01 b1 5a b9 b5 da e8 09 a9 1a fd 78 b8 da 5d 35 72 cb 27 d2 e8}  //weight: 1, accuracy: High
        $x_1_2 = {fc 06 93 24 ae 01 21 d2 28 2a ab 86 13 bd 37 48 f9 a8 ce 94 ff 03 b1 21 bf d3 f5 f5 54 5e c5 6e 27 20 7d 1b f9 fb 26 f4 d0 f3 02 76 57 09 83 c6 84 c0 21 ee 6b ef b8 b2 7a 02 54 75 af d8 73 0f 3f 4c c3 54 e0 ee d9 75 31 e1 ab bc 9e 45 10 0b 0c bf b8 f9 f4 f3 56 73 8e 76 2e a5 18 ba ce f8 ad 9b 0d 03 73 9b a9 e1 b3 e2 5e 7c b3 ca fd 7f 59 31 aa f3 27 06 ab 25 7d 9e 3f dc 03 7d 85 ba 9f 35 80 cd b1 7f 19 a9 39 ff 9c 3e 5b d3 41 e4 fc 65 a2 81 fd 6b d3 7d 94 1f 57 05 60 a9 b6 f1 57 09 76 2e c0 c0 57 ef b6 0a e9 21 d2 45 62 ff ae 50 3f 3d 07 49 e7 34 5f ab 9c 51 cb 1d 33 7b a1 ef bc 5b eb 14 97 42 2f 33 b4 56 ad e0 f3 17 e0 5e 6f 15 8c 54 3e 20 54 f2 ea c1 98 6d 64}  //weight: 1, accuracy: High
        $x_1_3 = {e6 93 0f 32 8a 62 79 64 3f af 6a 4f 55 34 cf d2 aa 0a 05 a1 d2 b7 1f 29 bb 1f 1b be 5a 4a 29 f8 8e f9 46 71 74 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 85 c0 0f 95 c1 8b 04 8d ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {89 ca 81 ca ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 21 d1 8d 34 09 f7 d6 01 ce 21 d6 01 f0 40 31 db ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 c0 8b 04 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff e0}  //weight: 1, accuracy: Low
        $x_1_4 = {01 c8 40 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 24 8b 54 24 10 8b 0c 82 89 5c 24 0c 8b 04 9a 8b 04 87 89 7c 24 04 8b 0c 8f 0f b7 74 05 1c 0f b7 5c 0d 1c 89 f2 89 74 24 14 39 de 72 02 89 da 89 5c 24 28 8d 34 28 8d 1c 28 83 c3 2e 8d 04 32 83 c0 2e 89 44 24 08 85 d2 74 4e 01 e9 83 c1 2e ?? ?? ?? ?? ?? 0f b6 13 89 d0 04 bf 3c 1a 73 03 80 c2 20 89 d6 0f b6 01 89 c2 80 c2 bf 80 fa 1a 73 02 04 20 8b 7c 24 04 89 f2 38 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wallets/Electrum" ascii //weight: 1
        $x_1_2 = "Wallets/ElectronCash" ascii //weight: 1
        $x_1_3 = "%appdata%\\com.liberty.jaxx\\IndexedDB" ascii //weight: 1
        $x_1_4 = "ExodusWeb3" ascii //weight: 1
        $x_1_5 = "wallets/Ethereum" ascii //weight: 1
        $x_1_6 = "%localappdata%\\Coinomi" ascii //weight: 1
        $x_1_7 = "keystore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lid=%s&j=%s&ver=4.0" ascii //weight: 1
        $x_1_2 = "TeslaBrowser/5.5" ascii //weight: 1
        $x_1_3 = "Screen.png" ascii //weight: 1
        $x_1_4 = "Screen Resoluton:" ascii //weight: 1
        $x_1_5 = "User:" ascii //weight: 1
        $x_1_6 = "Domain:" ascii //weight: 1
        $x_1_7 = "Workgroup:" ascii //weight: 1
        $x_1_8 = "Physical Installed Memory:" ascii //weight: 1
        $x_1_9 = "POST /api HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%appdata%\\com.liberty.jaxx" ascii //weight: 1
        $x_1_2 = "bitcoin" ascii //weight: 1
        $x_1_3 = "binance" ascii //weight: 1
        $x_1_4 = "Mail Clients/TheBat" ascii //weight: 1
        $x_1_5 = "Mail Clients/Pegasus" ascii //weight: 1
        $x_1_6 = "Applications/Telegram" ascii //weight: 1
        $x_1_7 = "Applications/1Password" ascii //weight: 1
        $x_1_8 = "Wallets/Daedalus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "appdata\\exodus" ascii //weight: 1
        $x_1_2 = "appdata\\binance" ascii //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 [0-80] 24 00 65 00 6e 00 76 00 3a 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 [0-80] 24 00 65 00 6e 00 76 00 3a 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6b 65 65 76 6f 2d 77 61 6c 6c 65 74 90}  //weight: 1, accuracy: High
        $x_1_5 = "electrum" ascii //weight: 1
        $x_1_6 = "onekey-wallet" ascii //weight: 1
        $x_1_7 = "env:appdata" ascii //weight: 1
        $x_1_8 = "get-wmiobject-classwin32_computersystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webextension@metamask.io" ascii //weight: 1
        $x_1_2 = "Electrum\\wallets" ascii //weight: 1
        $x_1_3 = "Bitcoin\\wallets" ascii //weight: 1
        $x_1_4 = "MetaMask" ascii //weight: 1
        $x_1_5 = "Password" ascii //weight: 1
        $x_1_6 = "Wallets/DashCore" ascii //weight: 1
        $x_1_7 = "Ronin Wallet" ascii //weight: 1
        $x_1_8 = "Leap Wallet" ascii //weight: 1
        $x_1_9 = "Agrent" ascii //weight: 1
        $x_1_10 = "localhost" ascii //weight: 1
        $x_1_11 = "params" ascii //weight: 1
        $x_1_12 = "exodus" ascii //weight: 1
        $x_1_13 = "Wallets/JAXX" ascii //weight: 1
        $x_1_14 = "keystore" ascii //weight: 1
        $x_1_15 = "Wallets/Binance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_Z_2147927310_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.Z!MTB"
        threat_id = "2147927310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Electrum" ascii //weight: 1
        $x_1_2 = "ElectronCash" ascii //weight: 1
        $x_1_3 = "Exodus" ascii //weight: 1
        $x_1_4 = "Ethereum" ascii //weight: 1
        $x_1_5 = "BitCoin" ascii //weight: 1
        $x_1_6 = "Binance" ascii //weight: 1
        $x_1_7 = "xverse" ascii //weight: 1
        $x_1_8 = "daedalus " ascii //weight: 1
        $x_1_9 = "leap" ascii //weight: 1
        $x_1_10 = "Glass" ascii //weight: 1
        $x_1_11 = "Ronin" ascii //weight: 1
        $x_1_12 = "Forniter" ascii //weight: 1
        $x_1_13 = "RABBY" ascii //weight: 1
        $x_1_14 = "Coinomi" ascii //weight: 1
        $x_10_15 = "keystore" ascii //weight: 10
        $x_10_16 = "JAXX" ascii //weight: 10
        $x_10_17 = "base64encode" ascii //weight: 10
        $x_10_18 = "decodebase64" ascii //weight: 10
        $x_10_19 = {66 69 6e 64 69 6e 67 20 63 65 6e 74 72 61 6c 20 64 69 72 65 63 74 6f 72 79 00}  //weight: 10, accuracy: High
        $x_10_20 = "password" ascii //weight: 10
        $x_10_21 = "user-agent" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 14 of ($x_1_*))) or
            ((7 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_RPL_2147927447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPL!MTB"
        threat_id = "2147927447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 a0 05 00 00 10 00 00 00 78 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 b0 05 00 00 00 00 00 00 88 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 c0 05 00 00 02 00 00 00 88 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPL_2147927447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPL!MTB"
        threat_id = "2147927447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 66 75 6e 63 36 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 36 2e 31 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 35 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 35 2e 31 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 34 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 34 2e 31 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 33 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 33 2e 31 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 32 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 32 2e 31 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 38 00 6d 61 69 6e 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 66 75 6e 63 37 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NDQ_2147927713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NDQ!MTB"
        threat_id = "2147927713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LOGS12--minecraf" ascii //weight: 2
        $x_1_2 = "MxS6v4btV3utz6cmibhanNn8WS6HIbsiCmt799JV" ascii //weight: 1
        $x_1_3 = {89 dd f7 d5 21 cd 89 e8 0f af ea 89 ca f7 d2 21 da 8b 1c 24 f7 d3 21 fb 0f af da f7 e2}  //weight: 1, accuracy: High
        $x_1_4 = {f7 e6 01 ca 0f af f5 01 d6 03 44 24 1c 11 de 03 44 24 04 11 fe 89 f7 c1 ef 15 31 f7 89 f3 0f a4 c3 0b 31 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPM_2147927904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPM!MTB"
        threat_id = "2147927904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 0c b7 95 e9 d1 5b 89 cd c1 ed 18 31 cd 69 cd 95 e9 d1 5b 69 d2 95 e9 d1 5b 31 ca 69 4c b7 04 95 e9 d1 5b 89 cd c1 ed 18 31 cd 69 cd 95 e9 d1 5b 69 d2 95 e9 d1 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPM_2147927904_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPM!MTB"
        threat_id = "2147927904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? 00 00 ?? ?? 00 00 00 06 00 00 00 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 66 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 64 00 65 00 66 00 4f 00 66 00 66 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: High
        $x_1_3 = "Software\\WinLicense" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PIP_2147928100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PIP!MTB"
        threat_id = "2147928100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 c2 0f b6 d2 0f b6 8c 15 ?? ?? ?? ?? 88 8c 35 ?? ?? ?? ?? 89 55 d0 88 84 15 c4 fe ff ff 02 84 35 c4 fe ff ff 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 8b 4d 08 8b 55 d8 30 04 11 42 89 55 d8 39 55 0c 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPN_2147928126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPN!MTB"
        threat_id = "2147928126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 20 20 20 20 20 b5 be 04 00 00 10 00 00 00 2c 02 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 20 20 20 20 20 20 20 20 cd 1f 00 00 00 d0 04 00 00 10 00 00 00 30 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 20 20 20 20 20 20 20 20 38 be 00 00 00 f0 04 00 00 1c 00 00 00 40 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20 08 32 00 00 00 b0 05 00 00 1a 00 00 00 5c 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPN_2147928126_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPN!MTB"
        threat_id = "2147928126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 80 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 88 03 00 00 00 90 06 00 00 04 00 00 00 90 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 94 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 44 03 00 00 00 90 06 00 00 02 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f0 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_3 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 80 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 00 10 00 00 00 90 06 00 00 10 00 00 00 90 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 10 00 00 00 a0 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_RPAA_2147928153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPAA!MTB"
        threat_id = "2147928153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 20 05 00 00 10 00 00 00 42 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 30 05 00 00 04 00 00 00 52 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 40 05 00 00 02 00 00 00 56 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SPDC_2147928256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SPDC!MTB"
        threat_id = "2147928256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 d0 00 c2 0f b6 d2 0f b6 8c 15 ?? ?? ?? ?? 88 8c 35 ?? ?? ?? ?? 89 55 d0 88 84 15 ?? ?? ?? ?? 02 84 35 ?? ?? ?? ?? 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 8b 4d 08 8b 55 d8 30 04 11 42 89 55 d8 39 55 0c 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPAC_2147928260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPAC!MTB"
        threat_id = "2147928260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 80 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 48 04 00 00 00 90 06 00 00 06 00 00 00 90 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 96 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BAN_2147928342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BAN!MTB"
        threat_id = "2147928342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e0 2e 74 61 67 67 61 6e 74 00 40 00 00 00 ?? ?? 00 00 22 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0}  //weight: 3, accuracy: Low
        $x_2_2 = {c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_5_3 = {e0 2e 72 73 72 63 00 00 00 00 05 00 00 00 60 00 00 00 06 00 00 00 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 38}  //weight: 5, accuracy: High
        $x_5_4 = {e0 2e 72 73 72 63 00 00 00 44 03 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f2 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_NIT_2147928350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NIT!MTB"
        threat_id = "2147928350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b7 75 00 8d 4e bf 66 83 f9 1a 73 03 83 ce 20 0f b7 0b 8d 41 bf 66 83 f8 1a 73 03 83 c9 20 66 85 f6 74 0b 83 c5 02 83 c3 02 66 39 ce 74 d1}  //weight: 2, accuracy: High
        $x_1_2 = {21 cf 09 f7 21 d7 09 c2 31 fa 80 c2 da 88 54 04 ef 40 49 83 f8 27 75 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NIT_2147928350_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NIT!MTB"
        threat_id = "2147928350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d9 80 c1 a8 32 0c 18 80 c1 b0 88 0c 18 43 83 fb 04 75 ec ff 25 ?? ?? ?? ?? 31 c9 39 10 0f 95 c1 31 c0 ff 24 8d ?? ?? ?? ?? 89 7d e8 8b 45 08 8b 48 3c 89 4d ec 8b 04 08 89 45 f0 89 f1}  //weight: 2, accuracy: Low
        $x_1_2 = {89 ca 80 c2 6d 32 14 08 80 c2 26 88 14 08 41 83 f9 14 75 ec}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 54 0e 94 89 d3 21 cb 00 db 28 da 0f b6 d2 01 ca 80 c2 28 88 54 0e 94 41 83 f9 70 75 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NIT_2147928350_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NIT!MTB"
        threat_id = "2147928350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 69 52 4e 67 72 77 38 33 36 52 79 45 0d 0a 4b 67 49 38 57 43 73 4b 62 41 30 5a 47 65 54 68 63 31 47 43 37 57 4e 33 6b 59 64 57 52 58 74 55 32 53 2b 61 75 4a 48 4d 70 41 31 37 44 4a 4d 79 4e 6d 73 6e 37 44 41 43 32 51 4b 42 67 44 62 33 0d 0a 6b 65 63 71 56 52 6c 78 6f 6e 41 71 50 55 46 5a 33 43 36 50 37 6b 53 58 4e 37 43}  //weight: 2, accuracy: High
        $x_2_2 = "AfSdNM6/46ObIJJmWHHvpVJ" ascii //weight: 2
        $x_1_3 = {66 bb 19 5a 66 83 c3 34 66 39 18 75 12 0f b7 50 3c 03 d0 bb e9 44 00 00 83 c3 67 39 1a 74 07 2d 00 10 00 00 eb da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_AMCT_2147928391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMCT!MTB"
        threat_id = "2147928391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 85 c0 0f 94 c1 8b 0c 8d ?? ?? ?? ?? [0-40] ff ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 08 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YYC_2147928499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YYC!MTB"
        threat_id = "2147928499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d3 c1 e2 04 03 55 ?? 33 55 f8 33 d1 2b fa 89 7d ec 8b 45 d4 29 45 f4 83 6d ?? 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPAD_2147928506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPAD!MTB"
        threat_id = "2147928506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d8 04 00 00 00 90 06 00 00 06 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f4 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b4 06 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 06 00 00 02 00 00 00 f2 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_RPAE_2147928521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPAE!MTB"
        threat_id = "2147928521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 74 65 78 74 00 00 00 9c a8 01 00 00 10 00 00 00 aa 01 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 64 61 74 61 00 00 24 8b 00 00 00 c0 01 00 00 8c 00 00 00 b2 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 6c 22 00 00 00 50 02 00 00 16 00 00 00 3e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPAF_2147928529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPAF!MTB"
        threat_id = "2147928529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 90 24 00 00 10 00 00 00 68 01 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 a0 24 00 00 04 00 00 00 78 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 b0 24 00 00 02 00 00 00 7c 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NIM_2147928720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NIM!MTB"
        threat_id = "2147928720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 0c 30 04 2f 83 fb 0f 75 0b 8b 4c 24 10 51 ff ?? ?? ?? ?? ?? 47 3b fb 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPAG_2147928939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPAG!MTB"
        threat_id = "2147928939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 80 73 00 00 10 00 00 00 36 28 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 90 73 00 00 02 00 00 00 46 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 73 00 00 02 00 00 00 48 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 10 76 00 00 10 00 00 00 3c 28 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 20 76 00 00 02 00 00 00 4c 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 30 76 00 00 02 00 00 00 4e 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_3 = {20 20 20 00 20 20 20 20 00 60 73 00 00 10 00 00 00 44 28 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 70 73 00 00 02 00 00 00 54 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 80 73 00 00 02 00 00 00 56 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
        $x_1_4 = {20 20 20 00 20 20 20 20 00 e0 70 00 00 10 00 00 00 78 27 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 f0 70 00 00 02 00 00 00 88 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 00 71 00 00 02 00 00 00 8a 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_AMCV_2147928954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.AMCV!MTB"
        threat_id = "2147928954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 e0 3b 45 e4 0f 8d ?? ?? ?? ?? 8b 45 e8 8b 4d e0 c1 e1 02 8b 04 08 89 45 f8 69 45 f8 ?? ?? ?? ?? 89 45 f8 8b 45 f8 c1 e8 18 33 45 f8 89 45 f8 69 45 f8 01 89 45 f8 69 45 ec 01 89 45 ec 8b 45 f8 33 45 ec 89 45 ec 8b 45 e0 83 c0 01 89 45 e0}  //weight: 4, accuracy: Low
        $x_1_2 = {0f be 00 33 45 d8 89 45 d8 69 45 d8 ?? ?? ?? ?? 89 45 d8 8b 45 d8 33 45 ec 89 45 ec 8b 45 ec c1 e8 0d 33 45 ec 89 45 ec 69 45 ec 00 89 45 ec 8b 45 ec c1 e8 0f 33 45 ec 89 45 ec 8b 45 ec 89 45 cc 8b 4d fc 31 e9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PZZ_2147929040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PZZ!MTB"
        threat_id = "2147929040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 ec c1 e8 05 89 45 f8 8b 45 dc 01 45 f8 8d 0c 3b 33 f1 81 3d ?? ?? ?? ?? e6 09 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_OOZ_2147929144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.OOZ!MTB"
        threat_id = "2147929144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 0f b6 84 34 18 01 00 00 8b 0c 24 00 c1 89 0c 24 0f b6 c9 0f b6 94 0c 18 01 00 00 88 94 34 18 01 00 00 88 84 0c 18 01 00 00 02 84 34 ?? ?? ?? ?? 0f b6 c0 0f b6 84 04 18 01 00 00 8b 8c 24 ?? ?? ?? ?? 30 04 19 43 3b 9c 24 34 02 00 00 0f 84}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_POV_2147929449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.POV!MTB"
        threat_id = "2147929449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d f4 8b 45 0c 66 8b 00 0f bf 55 ?? 89 14 24 0f b7 c0 89 44 24 04 ?? fe 05 00 00 83 ec 08 34 ff 88 45 f3 8a 45 f3 a8 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SBD_2147929951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SBD!MTB"
        threat_id = "2147929951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 c3 01 74 60 e0 4e b7 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPAH_2147929956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPAH!MTB"
        threat_id = "2147929956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 60 05 00 00 10 00 00 00 86 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 70 05 00 00 02 00 00 00 96 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 80 05 00 00 02 00 00 00 98 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YYV_2147930094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YYV!MTB"
        threat_id = "2147930094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 04 83 c0 46 89 04 24 83 2c 24 0a ?? 83 2c 24 ?? 8a 04 24 30 04 32 42 3b d7 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DD_2147930179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DD!MTB"
        threat_id = "2147930179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 04 ?? ?? ?? ?? 89 c2 21 ca 01 d2 29 d1 01 c1 89 ca f7 d2 81 e2 ed 00 00 00 83 e1 12 29 d1 fe c1 88 8c 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SXOX_2147931110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SXOX!MTB"
        threat_id = "2147931110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 f8 8d 0c 3a 8b 45 f0 c1 e8 05 89 45 fc 8b 45 dc 01 45 fc 33 f1 81 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NE_2147931489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NE!MTB"
        threat_id = "2147931489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 0d a8 74 21 01 64 8b 09 8b 39 83 ff 00 74 ?? 8b 6f 18 3b 7d 30}  //weight: 3, accuracy: Low
        $x_2_2 = {74 1a 8b 75 00 39 f7 74 13 e8 ?? ?? ?? ?? 8b 0d a8 74 21 01 64 8b 09 89 31 8b 66 1c 83 ec}  //weight: 2, accuracy: Low
        $x_1_3 = "new443agevia200404tcp" ascii //weight: 1
        $x_1_4 = "Gems Folder Size" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GPPG_2147931803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GPPG!MTB"
        threat_id = "2147931803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 80 c1 ?? 30 4c 04 02 40 83 f8 14 75 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GC_2147931814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GC!MTB"
        threat_id = "2147931814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.CocLYFOOoa" ascii //weight: 2
        $x_3_2 = "main.lFDfigPOFq" ascii //weight: 3
        $x_1_3 = "main.RDF" ascii //weight: 1
        $x_1_4 = "main.CONTEXT" ascii //weight: 1
        $x_1_5 = "XORKey" ascii //weight: 1
        $x_2_6 = "main.ISLAdTJUKL" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SKE_2147931944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SKE!MTB"
        threat_id = "2147931944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 89 b5 10 f9 ff ff ff 15 80 02 44 00 89 ?? ?? ?? ff ff 33 db 8d 85 f0 f5 ff ff 89 ?? ?? ?? ff ff 50 53 ff 15 28 02 44 00 8b 35 30 02 44 00 eb 1a}  //weight: 1, accuracy: Low
        $x_1_2 = "Screenshoter: Screen Uploader" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GPPH_2147932611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GPPH!MTB"
        threat_id = "2147932611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e0 03 8a 44 05 ?? 30 04 0b 41 3b ce 72 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_HGP_2147932750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.HGP!MTB"
        threat_id = "2147932750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 72 1c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GPKY_2147933420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GPKY!MTB"
        threat_id = "2147933420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8D343781E6FF000000885C08080FB67430088B3C2489F3301C1783C2013B54242475B089" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PB_2147933496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PB!MTB"
        threat_id = "2147933496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c6 83 e6 08 89 ca 83 f2 64 01 f2 32 54 0c ?? 80 c2 38 88 54 0c ?? 41 83 c0 02 83 f9 14 75 ?? 8d 44 24 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PC_2147933497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PC!MTB"
        threat_id = "2147933497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 bc 1e [0-4] 89 d0 25 [0-4] 89 d9 81 e1 [0-4] 09 c1 81 f1 [0-4] 8d 82 [0-4] 21 c1 09 f9 21 f8 f7 d1 09 c8 04 [0-4] 88 84 1e [0-4] 43 4a 81 fb [0-4] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DI_2147933587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DI!MTB"
        threat_id = "2147933587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 ca 8a 8c 0d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_10_2 = {30 0e ff c6 ?? ?? 0f 85}  //weight: 10, accuracy: Low
        $x_10_3 = {ff ff 30 0e e9}  //weight: 10, accuracy: High
        $x_10_4 = {30 0e ff c6 ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_DJ_2147933588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DJ!MTB"
        threat_id = "2147933588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 0e ff c6 e9 07 00 8a 8c 0d ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = {ff ff 02 ca e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PE_2147933686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PE!MTB"
        threat_id = "2147933686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 85 ff 74 11 8b c8 83 e1 03 8a 4c 0d 10 30 0c 06 40 3b c7 72 ef ff 45 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_EAP_2147934433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EAP!MTB"
        threat_id = "2147934433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c1 80 c1 95 32 4c 04 04 80 c1 d6 88 4c 04 04 89 c1 83 e1 01 83 f0 01 8d 04 48}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GVA_2147934993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GVA!MTB"
        threat_id = "2147934993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 9c c0 0f 9c 44 24 ?? 30 c3 89 da f6 d2 20 c2 89 d0 30 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GVA_2147934993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GVA!MTB"
        threat_id = "2147934993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 ca 8a 8c 0d ?? ?? ?? ?? 30 0e ff c6 ff cf fe c3 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? 88 94 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DK_2147935086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DK!MTB"
        threat_id = "2147935086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff ff 30 0e e9 05 00 8a 8c 0d}  //weight: 10, accuracy: Low
        $x_1_2 = {ff ff 02 ca e9 0c 00 88 8c 1d ?? ?? ff ff 88 94 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_INS_2147935101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.INS!MTB"
        threat_id = "2147935101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f e4 1c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PD_2147935809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PD!MTB"
        threat_id = "2147935809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 fa 89 15 [0-4] 0f bf 05 [0-4] 0f af 05 [0-4] 66 a3 [0-4] 8b 8d [0-4] 0f af 0d [0-4] 89 8d [0-4] 0f bf 15 [0-4] 03 95 [0-4] 66 89 15 [0-4] 0f bf 85 [0-4] 03 05 [0-4] 66 89 85 [0-4] 0f bf 0d [0-4] 0f af 0d [0-4] 89 0d [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YIN_2147936426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YIN!MTB"
        threat_id = "2147936426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b cf 33 d7 2b cf 81 c7 cd 60 00 00 33 f8 2b f8 33 c7 33 d7 2b f8 03 ca b8 9b db cd 19 33 f9 69 d2 ?? ?? ?? ?? 33 fa 03 d1 81 f2 5e 00 00 00 03 fa 33 fa 66 81 ea 5e 0e 81 f0 f5 af a9 75 c7 85 00 fa ff ff 3a 0d 00 00 69 d2 b5 82 00 00 33 fa e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SSPC_2147936928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SSPC!MTB"
        threat_id = "2147936928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 20 00 b0 70 00 00 10 00 00 00 52 2b 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 bc 0a 01 00 00 c0 70 00 00 0c 01 00 00 62 2b 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 d0 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_STA_2147937193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STA"
        threat_id = "2147937193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 10, accuracy: High
        $x_1_2 = "\"v\": \"Password\"," ascii //weight: 1
        $x_1_3 = "\"ez\": \"Ronin Wallet\"" ascii //weight: 1
        $x_1_4 = "\"ez\": \"Binance Chain Wallet\"" ascii //weight: 1
        $x_1_5 = "\"p\": \"%appdata%\\\\Ethereum\"," ascii //weight: 1
        $x_1_6 = "\"p\": \"%appdata%\\\\Bitcoin\\wallets\"," ascii //weight: 1
        $x_1_7 = "\"p\": \"%localappdata%\\\\Microsoft\\\\Edge\\\\User Data\"," ascii //weight: 1
        $x_1_8 = "\"z\": \"Wallets/Bitcoin core\"," ascii //weight: 1
        $x_1_9 = "\"z\": \"Wallets/DashCore\"," ascii //weight: 1
        $x_1_10 = "\"n\": \"chrome.exe\"," ascii //weight: 1
        $x_1_11 = "\"en\": \"ejbalbakoplchlghecdalmeeeajnimhm\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_STB_2147937195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STB"
        threat_id = "2147937195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe ff ff ff 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_2 = {b8 ff ff ff ff 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_2_3 = {0f b6 5d 00 53 e8 ?? ?? ?? ?? 83 c4 04 85 c0 74 ?? 45 90 90 90 90 90 90}  //weight: 2, accuracy: Low
        $x_2_4 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf}  //weight: 2, accuracy: Low
        $x_10_5 = {57 58 59 5a 00 78 58 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_STC_2147937197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STC!!LummaStealer.STC"
        threat_id = "2147937197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "LummaStealer: an internal category used to refer to some threats"
        info = "STC: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"v\": \"Password\"," ascii //weight: 1
        $x_1_2 = "\"ez\": \"Ronin Wallet\"" ascii //weight: 1
        $x_1_3 = "\"ez\": \"Binance Chain Wallet\"" ascii //weight: 1
        $x_1_4 = "\"p\": \"%appdata%\\\\Ethereum\"," ascii //weight: 1
        $x_1_5 = "\"p\": \"%appdata%\\\\Bitcoin\\wallets\"," ascii //weight: 1
        $x_1_6 = "\"p\": \"%localappdata%\\\\Microsoft\\\\Edge\\\\User Data\"," ascii //weight: 1
        $x_1_7 = "\"z\": \"Wallets/Bitcoin core\"," ascii //weight: 1
        $x_1_8 = "\"z\": \"Wallets/DashCore\"," ascii //weight: 1
        $x_1_9 = "\"n\": \"chrome.exe\"," ascii //weight: 1
        $x_1_10 = "\"en\": \"ejbalbakoplchlghecdalmeeeajnimhm\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_LummaStealer_STD_2147937198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STD!!LummaStealer.STD"
        threat_id = "2147937198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "LummaStealer: an internal category used to refer to some threats"
        info = "STD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fe ff ff ff 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_2 = {b8 ff ff ff ff 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_2_3 = {0f b6 5d 00 53 e8 ?? ?? ?? ?? 83 c4 04 85 c0 74 ?? 45 90 90 90 90 90 90}  //weight: 2, accuracy: Low
        $x_2_4 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf}  //weight: 2, accuracy: Low
        $x_10_5 = {57 58 59 5a 00 78 58 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_EA_2147937247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.EA!MTB"
        threat_id = "2147937247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 ce 83 e6 06 89 d3 81 f3 8b 00 00 00 01 f3 32 1c 14 80 c3 49 88 1c 14 42 83 c1 02 83 fa 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_STE_2147937489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STE"
        threat_id = "2147937489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 49 44 41 54}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 d2 c1 e1 05 81 e1 e0 7f 00 00 31 d1 0f b7 94 4e 72 92 02 00 89 c7 81 e7 ff 7f 00 00 66 89 94 7e 72 92 01 00 89 da 42 66 89 84 4e 72 92 02 00 45}  //weight: 1, accuracy: High
        $x_1_3 = {ae 42 60 82 c7 ?? ?? ?? 49 45 4e 44}  //weight: 1, accuracy: Low
        $x_1_4 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_LummaStealer_STF_2147937492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STF!!LummaStealer.STF"
        threat_id = "2147937492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "LummaStealer: an internal category used to refer to some threats"
        info = "STF: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 49 44 41 54}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 d2 c1 e1 05 81 e1 e0 7f 00 00 31 d1 0f b7 94 4e 72 92 02 00 89 c7 81 e7 ff 7f 00 00 66 89 94 7e 72 92 01 00 89 da 42 66 89 84 4e 72 92 02 00 45}  //weight: 1, accuracy: High
        $x_1_3 = {ae 42 60 82 c7 ?? ?? ?? 49 45 4e 44}  //weight: 1, accuracy: Low
        $x_1_4 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_LummaStealer_RJP_2147937610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RJP!MTB"
        threat_id = "2147937610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 89 c6 68 f0 fc 54 a1 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DIZ_2147937648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DIZ!MTB"
        threat_id = "2147937648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 f3 0f b6 5c 34 04 01 d3 00 db 80 f3 55 89 d9 d0 e9 00 d9 88 d5 0f b6 f1 80 e5 0f 32 2c 17 8d 1c 76 30 dd 88 2c 17 8b 8c 24 ?? ?? ?? ?? 42 39 d1 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PI_2147937796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PI!MTB"
        threat_id = "2147937796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3 89 c8 04 bf 3c 1a 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PI_2147937796_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PI!MTB"
        threat_id = "2147937796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d3 c1 eb 0c 80 e3 3f 80 cb 80 88 5e 01 c1 ea 06 80 e2 3f 80 ca 80 88 56 02 83 e1 3f 89 ca 83 f2 3f 83 f1 7f 09 d1 f6 d1 88 4e 03 b9 04 00 00 00 01 ce e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZA_2147938090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZA!MTB"
        threat_id = "2147938090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 2c a5 bb 2b 97 3d ba 89 d4 65 8e cb 3b db e5 39 1d 90 c4 de 39 6f b3 cd 63 bd a5 a8 85 f0 4c 98 aa 97 1b 50 d5 05 e6 c3 39 f3 33 66 76 b9 e2 bf 28 27 75 5b be b0 7d 98 4a b3 f2 d4 46 3b ff 19 27 c8 15 8a 4f 07 22 ec cc 7b 67 39 16 1f 0e 83 cf 84 6f 7a e4 47 5b 60 b3 3d 91 d4 b2 44 ea 74 5a df ee a0 8d 5c 6e c9 14 34 7c d1 b5 62 7d be a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZK_2147938094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZK!MTB"
        threat_id = "2147938094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 39 e7 25 ca 8c f5 b2 45 37 4d f7 95 a6 c3 22 c0 24 0f c9 d0 08 a4 65 f9 a9 bd de 72 84 81 fe 85 cc 7b 61 48 86 a1 0f ad 61 ef b9 21 cd 32 1f c5 b7 e9 a3 4f 86 6b 9d 15 bd 08 d7 be 4f 09 56 23 7f bd 25 9c cf 05 0d e2 2b 8c 1b 55 6e 2a 32 3a a6 d6 f4 44 92 6d 61 47 a4 d2 ca fb 7f 9c dc 5d a1 ce 41 03 b9 a3 ce 1a 56 bd 4d 0a ef a3 64 46 3b cb ac 4c 1c 20 e7 5c a0 68 14 59 33 d9 56 af 48 4e 36 99 a7 09 31 65 73 8a 47 7e 7e b0 97 dd d9 55 26 89 13 49 20 4c da a8 1a 7a d3 c0 26 c9 e9 36 7c 6a 68 e2 f3 f5 04 d8 ec fd 6f 87 0f da 43 3f f7 7c 71 0b c8 27 47 4c f9 a9 c4 0b f5 93 f3 6f d1 05 27 df 5d ae be 3d 6b ac 6a 8e 8c e3 04 a2 9e cb 28 ee 89 d6 2b b6 f1 e3 43 d6 c2 cb b9 89 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DM_2147938203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DM!MTB"
        threat_id = "2147938203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {47 96 6e 8a 73 46 95 35 a8 33 66 2c 32 cb 59 58 58 2e ad 2c 22 cf}  //weight: 10, accuracy: High
        $x_10_2 = {89 f8 83 e0 02 89 f9 83 cf 02 0f af f8 83 f0 02 83 e1 fd 0f af c8 01 cf 83 ff 04 72}  //weight: 10, accuracy: High
        $x_10_3 = {0f b6 d2 c1 e1 05 81 e1 e0 7f 00 00 31 d1 0f b7 94 4e 72 92 02 00 89 c7 81 e7 ff 7f 00 00 66 89 94 7e 72 92 01 00 89 da 42 66 89 84 4e 72 92 02 00 45}  //weight: 10, accuracy: High
        $x_10_4 = {c5 0e 04 45 0b 03 56 01 0e b0 01 43 0e c0 01 02 8c 0a 0e 14 41 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_SYPC_2147938400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SYPC!MTB"
        threat_id = "2147938400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 20 00 d0 05 00 00 10 00 00 00 d0 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 e0 05 00 00 02 00 00 00 e0 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 f0 05 00 00 02 00 00 00 e2 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_SUPC_2147938401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.SUPC!MTB"
        threat_id = "2147938401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 90 0a 00 00 10 00 00 00 7a 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 84 58 4e 00 00 a0 0a 00 00 10 28 00 00 8a 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 00 59 00 00 02 00 00 00 9a 2c 00 00 00 00 00 00 00 00 00 00 00 00 00 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MMR_2147938689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MMR!MTB"
        threat_id = "2147938689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 2c d8 8b 32 8b 7a 04 89 34 2a 89 7c 2a 04 43 8d 69 ff 39 eb 7c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GVB_2147938992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GVB!MTB"
        threat_id = "2147938992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 cb 44 08 c8 34 01 08 d8 44 89 da 80 f2 01 45 30 c3 44 08 d2}  //weight: 2, accuracy: High
        $x_1_2 = {0f 9c c2 0f 9c 45 ?? 89 d3 30 c3 20 d3 44 20 c9 20 c2 08 ca 89 d8 30 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YA_2147939087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YA!MTB"
        threat_id = "2147939087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".name" wide //weight: 1
        $x_1_4 = "value" wide //weight: 1
        $x_1_5 = "|where-object" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZB_2147939634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZB!MTB"
        threat_id = "2147939634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 cb 10 66 32 c5 10 66 78 ce 03 66 1e 6b 10 66 03 88 04 66 12 af 0f 66 88 83 03 66 bc c8 0e 66 87 69 10 66 d6 c5 10 66 67 90 05 66 00 46 01 66 ef 60 10 66 b8 49 01 66 0d 16 11 66 70 17 04 66 d4 d9 01 66 51 e2 00 66 d4 68 10 66 d3 a7 0f 66 6b a7 0e 66 3e da 01 66 6d d7 01 66 af 0e 0f 66 5a ae 0f 66 a0 d4 0e 66 3a 16 04 66 bb c4 0e 66 f1 d9 00 66 34 c8 0e 66 23 31 0f 66 a8 c6 10 66 23 a3 00 66 b3 68 05 66 ed ee 0f 66 5f 28 04 66 21 9f 0e 66 a5 3f 0f 66 c2 27 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZC_2147939635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZC!MTB"
        threat_id = "2147939635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 54 8d 25 99 09 20 36 1b d1 a0 29 4c 3e 6e a2 8c bd 39 3a 14 06 75 f9 8b 82 4f 8f e6 6c cc 5a 92 9f 58 f3 09 38 c6 62 53 43 87 51 f8 aa e4 e2 9b f7 48 e1 b4 c1 da 21 0e 6d 2b 28 a1 bb 93 36 f4 9c ec 11 8d 7e 82 f5 e3 8f e6 fb 58 0a 33 17 14 71 36 82 b3 fc 5b ee 0d 1c d8 45 3a ea 5b 13 8a 01 9c d7 d2 ae db 2e 87 9e 0b 02 85 c1 14 3c 43 db 02 9f 81 7e 60 f4 7b 6b 7f f6 3e 77 b0 d7 d6 80 c5 07 f9 28 5e 84 c0 69 9c a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZD_2147939756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZD!MTB"
        threat_id = "2147939756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 2c 0d 68 2a 07 0d 4c 8b 67 09 cd 2d e8 4c 2c 27 ac 4c 0d 0b ac c7 67 2b ac 4c 6d c9 08 8a 6c 89 0c e6 8d c8 66 28 2c 8b 0c 29 c8 47 4b aa 86 ab 48 0b 86 ac 68 8a cc 07 ac 0c c7 28 a8 66 67 2b 28 c9 2d e8 aa 8d a9 eb ad e6 ec 4a cb 2d ed 0d 0c a7 ac a7 45 07 aa ac 0d 4c 88 2a 47 ca 09 6b 2d 45 87 69 ab 4e 07 c9 29 cc a7 cb e7 aa 45 ec 6c ea ac 0c a8 45 ea c8 86 8d 08 29 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZE_2147939757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZE!MTB"
        threat_id = "2147939757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 34 c1 c3 0c 01 c8 05 4e fd 53 a9 89 04 24 01 eb c1 c2 0a 89 f8 31 d0 21 d8 31 d0 03 6c 24 40 01 e8 05 e9 76 6d 7a c1 c0 05 01 f0 c1 c7 0a 89 d9 31 f9 21 c1 31 f9 8b 6c 24 54 01 ee 01 f1 81 c1 e9 76 6d 7a c1 c1 0f 01 d1 c1 c3 0a 89 c6 31 de 21 ce 31 de 03 54 24 30 01 f2 81 c2 e9 76 6d 7a c1 c2 08 01 fa 03 7c 24 1c c1 c0 0a 89 ce 31 c6 31 d6 01 f7 c1 c7 08 01 df 03 5c 24 34 c1 c1 0a 89 d6 31 ce 31 fe 01 f3 c1 c3 05 01 c3 01 e8 c1 c2 0a 89 fe 31 d6 31 de 01 f0 c1 c0 0c 01 c8 03 4c 24 2c c1 c7 0a 89 de 31 fe 31 c6 01 f1 c1 c1 09 01 d1 03 54 24 24 c1 c3 0a 89 c6 31 de 31 ce 01 f2 c1 c2 0c 01 fa 03 7c}  //weight: 1, accuracy: High
        $x_1_2 = {24 3c c1 c0 0a 89 ce 31 c6 31 d6 01 f7 c1 c7 05 01 df 03 5c 24 38 c1 c1 0a 89 d6 31 ce 31 fe 01 f3 c1 c3 0e 01 c3 03 44 24 40 c1 c2 0a 89 fe 31 d6 31 de 01 f0 c1 c0 06 01 c8 03 4c 24 44 c1 c7 0a 89 de 31 fe 31 c6 01 f1 c1 c1 08 01 d1 03 54 24 48 c1 c3 0a 89 c6 31 de 31 ce 01 f2 8b 34 24 c1 c6 05 8b 6c 24 04 01 ee 89 34 24 8b 74 24 58 01 f5 89 6c 24 04 c1 c2 0d 01 fa 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZF_2147939758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZF!MTB"
        threat_id = "2147939758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 72 9a e0 e8 07 e2 97 33 4f 15 ed 85 87 24 ba 81 aa 59 39 c2 20 d9 81 5f d9 cb f2 95 b4 50 ab 7e 7c 29 3e 55 54 74 e9 9b 64 cb a8 8c 95 38 79 e9 3e 4b 06 c3 ee 14 46 08 c6 0c cb 6b 79 d6 8d 50 5b 45 1f 88 48 c8 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZG_2147939759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZG!MTB"
        threat_id = "2147939759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 74 da 6d 39 bf eb 69 b8 60 2f 1f 52 90 f4 28 7e 99 53 e0 d8 bc c4 50 2c 7d 84 d5 56 52 f4 42 ce 3c 7c b7 bc 44 c2 7c bb 64 50 90 c9 c0 e7 25 ca 0c a0 f8 ce 83 79 3d 6f f4 18 13 62 2d 37 bc 10 f2 8d 41 0b e1 4a f0 0c 6c 42 d4 73 0f d9 5b 5d f4 4e 6e 7e 6a 1b 13 3c 87 72 7d cb e9 10 88 2f 5a db 81 ac fc 96 7b 56 70 e5 a8 ea c7 3f dd 7f 22 34 6b 48 95 21 c7 d4 fd 4d f6 7e 41 91 4d ca f1 16 5b d3 e2 31 0f 74 6e dc 5e bd 2c 11 17 29 8e 85 f2 1f 34 d9 9e 84 f3 47 2d 19 4b da db 4f c6 a3 5c 87 d3 64 e0 f1 95 99 8e bf 35 86 ff d9 35 c6 96 e1 18 d0 2d 81 4b b0 59 fb c8 d2 0a ab ae 20 9d 58 83 80 2d d6 7f d8 83 da 50 63 b8 df 06 28 4b 2c f4 6d eb ea c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_MBX_2147939971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.MBX!MTB"
        threat_id = "2147939971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii //weight: 1
        $x_1_2 = "aeblfdkhhhdcdjpifhhbdiojplfjncoa" ascii //weight: 1
        $x_1_3 = "jnlgamecbpmbajjfhmmmlhejkemejdma" ascii //weight: 1
        $x_1_4 = "dlcobpjiigpikoobohmabehhmhfoodbb" ascii //weight: 1
        $x_1_5 = "jgaaimajipbpdogpdglhaphldakikgef" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_LummaStealer_DP_2147939987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DP!MTB"
        threat_id = "2147939987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c7 09 d7 21 c2 81 f6 ?? ?? ?? ?? 09 d6 8d 14 36 f7 d2 01 f2 21 fa 89 54 24 1c 8b 54 24 1c 80 c2 66 88 94 04}  //weight: 10, accuracy: Low
        $x_10_2 = {89 fb f7 d3 01 d3 29 d7 89 da 31 fa 21 ca 31 fa 09 cb 21 d3 89 5c 24 18 8b 4c 24 18 80 c1 5c 88 8c 04}  //weight: 10, accuracy: High
        $x_10_3 = {89 ce 09 d6 89 c7 21 d7 f7 d7 f7 d6 01 d6 21 fe 89 74 24 0c 8b 54 24 0c 80 c2 18 88 54 04 d0}  //weight: 10, accuracy: High
        $x_10_4 = {89 ca 81 e2 ?? ?? ?? ?? 89 ce 81 e6 ?? ?? ?? ?? 81 c9 ?? ?? ?? ?? 0f af ce 81 f6 ?? ?? ?? ?? 0f af f2 01 f1 8d 14 08 4a 8b 0d ?? ?? ?? ?? 89 14 81}  //weight: 10, accuracy: Low
        $x_10_5 = {89 fe 83 e6 01 f7 de 21 de 83 cf 02 0f af fd 01 ca 29 fa 01 f2 69 ca ?? ?? ?? ?? 01 c1 49 8b 15 ?? ?? ?? ?? 89 0c 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_DT_2147939993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DT!MTB"
        threat_id = "2147939993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {85 c9 0f 49 d1 81 e2 ?? ?? ?? ?? 89 c8 29 d0 0f b6 d3 8d 14 52 8b bc 24 ?? ?? ?? ?? 32 04 0f 30 d0 88 04 0f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGL_2147940187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGL!MTB"
        threat_id = "2147940187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 ca 21 f2 89 d1 f7 d1 83 e1 ?? 83 f2 ?? 8d 0c 4a 88 8c 04 ?? ?? ?? ?? 40 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DS_2147940286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DS!MTB"
        threat_id = "2147940286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f3 81 ce ?? ?? ?? ?? 0f af f7 81 f7 ?? ?? ?? ?? 81 e3 ?? ?? ?? ?? 0f af df 01 de 89 f7 21 d7 31 d6 8d 3c 7e 89 3c 88}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 3c 32 21 f2 01 d2 29 d7 89 7c 24 20 8b 54 24 20 89 d6 83 f6 5b 83 e2 5b 8d 14 56 fe c2 8b 34 24 88 54 34 10 ff 04 24}  //weight: 10, accuracy: High
        $x_10_3 = {f7 d0 8d 04 42 40 21 c8 89 44 24 20 8b 44 24 20 05 ?? ?? ?? ?? 89 c1 83 e1 01 83 f0 01 8d 04 48 88 44 1c 18}  //weight: 10, accuracy: Low
        $x_10_4 = {f7 d2 81 e7 ?? ?? ?? ?? 81 e2 ?? ?? ?? ?? 0f af d7 89 cf 81 e7 ?? ?? ?? ?? 81 c9 ?? ?? ?? ?? 0f af cf 01 d1 8d 14 08 4a 8b 0d ?? ?? ?? ?? 89 14 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_ZI_2147940288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZI!MTB"
        threat_id = "2147940288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 57 c6 ad 0c 72 de f9 c5 91 52 8f 25 8a 03 67 15 ec 15 f5 d1 76 08 62 93 c4 7f 1a 80 60 f6 7f 34 f4 3a 14 a5 ae 69 b7 8a 2f 82 e1 e2 1f 91 1d ee 7d 22 4d 47 db 17 11 a2 91 04 32 51 a2 6a b0 76 5b 97 49 c5 bc 5e 05 99 18 42 8e 38 a3 55 e1 37 a0 9d a9 fc bd 2b bc 10 77 51 fd 8f ac e5 f4 42 9b 9f ec 69 3c 98 90 24 ae 71 98 c1 2a 55 d6 a7 f9 ae 73 4c bd 73 bb f4 7f 7a ae 58 90 bf 45 33 5c 56 ce 40 a3 80 5d 92 a9 bb 3b 99 39 71 cf bf 44 13 2e 93 f2 5f d3 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZJ_2147940289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZJ!MTB"
        threat_id = "2147940289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 6b 0d 5e 4b 47 ee 08 e3 8f ec a1 4b 76 67 87 ab c1 9c 27 28 b7 54 7a 67 d7 8a 84 e5 e0 fe ef 1c 27 a6 f6 0e 17 47 d6 7a ca 99 91 b2 02 da 81 05 34 3e 68 9d 69 b9 f5 cb f5 7f d2 12 86 a6 67 91 41 a9 4d ec af 6b a9 9b 61 90 fd ac 8e be ad f1 58 bd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZL_2147940290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZL!MTB"
        threat_id = "2147940290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MjRmODU0Njk1YWVlNmQ3NGI2ZDFlZGQ2ZGZkYWY0NTJkMzRlNzMzMTA4NTA0MTA0OTJhZGQzNWFiNTVkZDA0Mw=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZM_2147940291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZM!MTB"
        threat_id = "2147940291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 36 a1 81 19 57 cf d2 19 57 cf d2 19 57 cf d2 0d 3c cc cd 31 25 7c fd 20 d3 cc ad 39 15 7c fd 20 d3 cc bd 30 b5 7c fd 20 d3 cc ed 31 d5 7c fd 23 e9 1b 4d 21 a5 7c fd 21 95 7c ed 27 b5 7c fd 24 b2 2c ad 30 45 7c fd 24 b2 2c bd 31 65 7c fd 24 b2 2c cd 30 85 7c fd 21 95 7c fd 21 85 7c fd 2d 42 2c fd 31 85 7c fd 2d 42 2c dd 31 85 7c fd 25 26 96 36 81 95 7c fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GVF_2147940466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GVF!MTB"
        threat_id = "2147940466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c7 2b cd f7 de 81 f1 60 9b b7 35 03 dd 87 c6 33 d0 81 eb 7c 09 51 1b 83 c1 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GVG_2147940727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GVG!MTB"
        threat_id = "2147940727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 33 ff 33 c9 89 7d 08 8b c1 83 e0 03 8a 44 05 08 30 04 0a 41 3b ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DV_2147940745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DV!MTB"
        threat_id = "2147940745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 b4 3c ?? ?? ?? ?? 89 fd 09 f5 21 fe 89 f0 83 e0 38 35 ?? ?? ?? ?? 89 f2 81 f2 ?? ?? ?? ?? 81 ce ?? ?? ?? ?? 21 d6 09 c6 81 f6 ?? ?? ?? ?? 21 ee 89 74 24 28 8b 44 24 28 04 88 88 84 3c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DW_2147940746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DW!MTB"
        threat_id = "2147940746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 cf 81 e7 ?? ?? ?? ?? 81 cf ?? ?? ?? ?? 31 f7 21 cb 8d 34 2b 46 8b 1c 24 09 fe 8d 04 50 89 f2 f7 d2 09 c2 8d 04 16 40 89 44 24 1c 8b 44 24 1c 04 34 88 84 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DX_2147940747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DX!MTB"
        threat_id = "2147940747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 c1 ea 1e f7 d0 89 d6 09 c6 21 d0 8d 14 36 f7 d2 01 f2 09 c2 69 c2 ?? ?? ?? ?? 01 c8 48 8b 15 ?? ?? ?? ?? 89 04 8a 41 81 f9 ?? ?? ?? ?? 75 cf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DY_2147940748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DY!MTB"
        threat_id = "2147940748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 ca c1 ea 1e 31 ca 69 ca ?? ?? ?? ?? 01 c1 41 8b 15 ?? ?? ?? ?? 89 4c 82 08 3d ?? ?? ?? ?? 74 ?? 89 ca c1 ea 1e 31 ca 69 ca ?? ?? ?? ?? 01 c1 83 c1 02 8b 15 ?? ?? ?? ?? 89 4c 82 0c 83 c0 02 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DAA_2147940932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DAA!MTB"
        threat_id = "2147940932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d1 c1 e9 1e 31 d1 89 ca 81 e2 ?? ?? ?? ?? 89 cf 81 c9 ?? ?? ?? ?? 0f af ca 81 f2 ?? ?? ?? ?? 81 e7 ?? ?? ?? ?? 0f af fa 01 f9 8d 14 08 4a 8b 0d ?? ?? ?? ?? 89 14 81 40 3d ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZAK_2147941370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZAK!MTB"
        threat_id = "2147941370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7c 24 24 10 8b 44 24 10 73 04 8d 44 24 10 8b 54 24 20 6a 00 8d 4c 24 10 51 52 50 a1 68 ad 58 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZBK_2147941371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZBK!MTB"
        threat_id = "2147941371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 04 19 25 22 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZCK_2147941372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZCK!MTB"
        threat_id = "2147941372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 82 3a 18 b3 0f 69 38 e1 82 3a 87 b5 af 5e 19 e0 82 45 04 68 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZDK_2147941373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZDK!MTB"
        threat_id = "2147941373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d9 67 85 d1 9d 06 eb 82 9d 06 eb 82 9d 06 eb 82 4e 74 e8 83 91 06 eb 82 4e 74 ee 83 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZEK_2147941374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZEK!MTB"
        threat_id = "2147941374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 09 cb 89 e9 83 c9 fe 31 d9 89 cb 81 f3 14 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZHK_2147941375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZHK!MTB"
        threat_id = "2147941375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 78 87 b6 9f 54 b7 7d a9 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZHK_2147941375_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZHK!MTB"
        threat_id = "2147941375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 3e 4d 5a 0f 85 67 06 00 00 8b 7e 3c 81 3c 37 50 45 00 00 0f 85 c8 06 00 00 89 74 24 04 01 f7 66 81 7f 04 64 86 0f 85 10 07 00 00 6a 04 68 00 30 00 00 ff 77 50 6a 00 e8 d7 5d 01 00 85 c0 8b 74 24 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZFK_2147941376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZFK!MTB"
        threat_id = "2147941376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 f7 01 ff 29 df 8b 5d ec 09 d7 31 f2 8d 34 3f f7 d6 01 fe 09 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZGK_2147941377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZGK!MTB"
        threat_id = "2147941377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 fe 89 d5 21 fd 31 d7 01 f7 29 f7 29 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZIK_2147941379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZIK!MTB"
        threat_id = "2147941379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 44 24 28 10 00 00 00 48 89 74 24 20 48 c7 44 24 30 10 00 00 00 b8 ab 90 92 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZJK_2147941380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZJK!MTB"
        threat_id = "2147941380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 28 3b 82 87 c3 08 c6 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZKK_2147941381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZKK!MTB"
        threat_id = "2147941381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c6 48 89 7c 24 38 48 89 7c 24 30 c7 44 24 28 05 00 00 00 48 8d 45 0f 48 89 44 24 20 45 8b cc 4c 8d 45 93 33 d2 8b 4d b7 e8 2f d9 ff ff 44 8b f0 85 c0 0f 84 1b 01 00 00 48 89 7c 24 20 4c 8d 4d 97 44 8b c0 48 8d 55 0f 4c 8b 65 e7 49 8b cc ff 15 33 00 01 00 85 c0 0f 84 ee 00 00 00 8b d6 2b 55 bf 03 53 08 89 53 04 44 39 75 97 0f 82 e1 00 00 00 80 7d 8f 0a 75 3e b8 0d 00 00 00 66 89 45 8f 48 89 7c 24 20 4c 8d 4d 97 44 8d 40 f4 48 8d 55 8f 49 8b cc ff 15 ed ff 00 00 85 c0 0f 84 a8 00 00 00 83 7d 97 01 0f 82 a6 00 00 00 ff 43 08 ff 43 04 8b 53 04 48 3b 75 9f 0f 83 93 00 00 00 4c 8b 55 a7 4c 8b 4d ef 8b 4d bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZLK_2147941382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZLK!MTB"
        threat_id = "2147941382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 3e 4d 5a 0f 85 67 06 00 00 8b 7e 3c 81 3c 37 50 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DU_2147941391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DU!MTB"
        threat_id = "2147941391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 5c 24 1c 89 da f7 d2 89 d1 81 e1 fa 00 00 00 89 d8 83 e0 05 01 c0 81 ca fa 00 00 00 01 da 83 c2 06 29 d8 05 fa 00 00 00 21 d0 29 c8 88 44 2c 18}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DAB_2147941392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DAB!MTB"
        threat_id = "2147941392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 cf 89 c8 25 ?? ?? ?? ?? 81 e7 ?? ?? ?? ?? 09 c7 31 cf 81 f7 ?? ?? ?? ?? 8d 83 ?? ?? ?? ?? 21 e8 31 c8 21 f8 89 44 24 08 8b 44 24 08 04 ca 88 84 1c ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZMK_2147941453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZMK!MTB"
        threat_id = "2147941453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 53 94 d8 6a 4f c4 05 0b c6 d2 e0 af ba a8 2b c5 64 2f 2f c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCJX_2147941742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCJX!MTB"
        threat_id = "2147941742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {45 31 c5 33 1c ad ?? ?? ?? ?? 89 d8 c1 e8 ?? 83 e3 ?? c1 ef ?? 31 df}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZOK_2147941850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZOK!MTB"
        threat_id = "2147941850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 49 52 49 53 49 54 49 55 49 56 49 57 e8 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZQK_2147941851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZQK!MTB"
        threat_id = "2147941851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src\\executable_loader.rs" ascii //weight: 1
        $x_1_2 = {6a 04 68 00 30 00 00 ff 70 50 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_YTK_2147941878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.YTK!MTB"
        threat_id = "2147941878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 14 10 d1 d2 d3}  //weight: 1, accuracy: High
        $x_1_2 = {1e 01 de 46 21 d6 01 d7 47 01 f6 29 f7 21 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_STG_2147941958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STG"
        threat_id = "2147941958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 100, accuracy: High
        $x_2_2 = {74 24 2e 88 54 24 2f 66 c7 44 24 30 00 00 8b 54}  //weight: 2, accuracy: High
        $x_1_3 = {3d 8b 04 24 b9 13 00 80 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_4 = {d1 a0 75 ad 22 ab 52 37 67 50 13 8c e7 61 5a c5}  //weight: 1, accuracy: High
        $x_1_5 = {ce 88 84 0c 7a 37 52 4d 41 4e 81 f9 ba c8 ad b2}  //weight: 1, accuracy: High
        $x_1_6 = {45 00 57 69 6e 48 74 74 70 57 72 69 74 65 44 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_ZSK_2147941968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZSK!MTB"
        threat_id = "2147941968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 5c 7f 62 3d fe 26 56 28 74 7b 3d 70 62 9f 33 75 e4 0f b6 4c 24 6e 80 7c 24 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZTK_2147941969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZTK!MTB"
        threat_id = "2147941969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 14 10 d1 d2 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZUK_2147941970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZUK!MTB"
        threat_id = "2147941970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1e 01 de 46 21 d6 01 d7 47 01 f6 29 f7 21 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZVK_2147941971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZVK!MTB"
        threat_id = "2147941971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 71 fa 41 a0 46 f0 da 7d de 6a b3 49 e1 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZWK_2147941972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZWK!MTB"
        threat_id = "2147941972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 7c 19 d4 af 9b 62 b1 4f db 10 a2 a8 1c 4e f7 b2 33 05 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_CCJY_2147942018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.CCJY!MTB"
        threat_id = "2147942018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0f be 0c 16 31 c1 0f af cb 0f be 44 16 ?? 31 c8 0f af c3 0f be 4c 16 ?? 31 c1 0f af cb 0f be 44 16 ?? 31 c8 0f af c3 83 c2 ?? 39 d7 75}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLC_2147942028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLC!MTB"
        threat_id = "2147942028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c8 8b c3 25 ?? ?? ?? ?? ?? ?? 48 83 c8 ?? 40 33 c8 81 e1 ?? ?? ?? ?? ?? ?? 49 81 c9 ?? ?? ?? ?? 41 8b 45 ?? 30 0c 03 43 3b 5d ?? 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ABC_2147942037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ABC!MTB"
        threat_id = "2147942037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {d3 f8 89 45 a4 8b 4d c4 0f af 4d 08 89 4d c4 8b 15 ?? ?? ?? ?? 03 55 08 89 15}  //weight: 4, accuracy: Low
        $x_1_2 = "NDhC5o7cu5e30hYepEGFf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_STH_2147942049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.STH!!LummaStealer.STH"
        threat_id = "2147942049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "LummaStealer: an internal category used to refer to some threats"
        info = "STH: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 24 2e 88 54 24 2f 66 c7 44 24 30 00 00 8b 54}  //weight: 2, accuracy: High
        $x_1_2 = {3d 8b 04 24 b9 13 00 80 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_3 = {d1 a0 75 ad 22 ab 52 37 67 50 13 8c e7 61 5a c5}  //weight: 1, accuracy: High
        $x_1_4 = {ce 88 84 0c 7a 37 52 4d 41 4e 81 f9 ba c8 ad b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaStealer_GZZ_2147942339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GZZ!MTB"
        threat_id = "2147942339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 4c 24 ?? 8b 4c 24 ?? 89 ca 83 f2 ?? 83 e1 ?? 8d 0c 4a fe c1 88 8c 04 ?? ?? ?? ?? 40 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DAC_2147942355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DAC!MTB"
        threat_id = "2147942355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c1 83 f1 7e 83 e0 01 01 c0 29 c8 8b 4c 24 0c 04 89 88 01 46 41 83 c2 02 83 fa 08 0f 85 35}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DAD_2147942356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DAD!MTB"
        threat_id = "2147942356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c1 02 81 e1 ?? ?? ?? ?? 81 e7 ?? ?? ?? ?? 09 cf 81 f7 ?? ?? ?? ?? 09 f7 f7 d7 21 ef 8b 2c 24 89 7c 24 10 8b 4c 24 10 80 c1 f6 88 4c 04 09 40 4d 83 f8 07 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DAE_2147942357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DAE!MTB"
        threat_id = "2147942357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 0c 2c 89 c2 81 e2 ?? ?? ?? ?? 89 eb 83 e3 02 09 d3 31 cb 81 f3 ?? ?? ?? ?? 8d 55 64 21 ca f7 d2 21 da 89 54 24 08 8b 4c 24 08 80 c1 74 88 0c 2c 45 48 83 fd 04 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DAF_2147942358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DAF!MTB"
        threat_id = "2147942358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c0 e1 02 0f b6 c1 8b 4d fc c1 e9 06 0b c1 8b c8 c1 e9 03 33 c8 b8 ?? ?? ?? ?? f7 eb 03 d3 c1 fa 02 8b c2 c1 e8 1f 03 c2 2b c8 8d 04 cd 00 00 00 00 2b c1 03 c3 25 ?? ?? ?? ?? 79}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DAH_2147942359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DAH!MTB"
        threat_id = "2147942359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 a0 05 00 00 10 00 00 00 b0 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 78 03 00 00 00 b0 05 00 00 04 00 00 00 c0 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 c0 05 00 00 02 00 00 00 c4 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLE_2147942420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLE!MTB"
        threat_id = "2147942420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 74 0c ?? 89 c7 83 e7 ?? 89 ca 81 f2 ?? ?? ?? ?? 01 fa 89 d7 f7 d7 21 f7 89 d3 31 f3 01 f3 29 fb 21 f2 f7 d2 21 da 89 14 24 8b 14 24 80 c2 9c 88 54 0c ?? 41 83 c0 ?? 83 f9 ?? 75}  //weight: 5, accuracy: Low
        $x_5_2 = {89 fb 09 f3 21 d6 09 ce 81 f6 ?? ?? ?? ?? 89 f9 09 d1 21 f1 21 d3 89 da f7 d2 8d 14 53 42 21 ca 89 55 ?? 8b 4d ?? 80 c1 ?? 88 8c 38 ?? ?? ?? ?? 47 81 ff ?? ?? ?? ?? 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_BD_2147942562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BD!MTB"
        threat_id = "2147942562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 4d 0c 0f bf 55 f4 0f af d1 66 89 55 f4 0f b7 45 08 0f b6 4d ff 03 c8 88 4d ff}  //weight: 3, accuracy: High
        $x_2_2 = {03 d1 88 95 ?? ?? ?? ff 0f bf 85 ?? ?? ?? ff 03 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BE_2147942619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BE!MTB"
        threat_id = "2147942619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 54 24 0f 0f b6 54 24 0f 32 91 ?? ?? ?? ?? 88 54 24 0f 8b 54 24 08 81 c2 ?? ?? ?? ?? 89 54 24 08 83 c0 01 83 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGA_2147942762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGA!MTB"
        threat_id = "2147942762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a c1 c0 e8 04 32 04 16 32 c1 8b 4d ?? 32 45 ?? 88 04 16 8b 45 ?? 40 89 4d f8 89 45 ?? 3b cb 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_BF_2147942833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.BF!MTB"
        threat_id = "2147942833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 54 24 ?? 83 c0 01 32 11 88 54 24 ?? 0f b6 54 24 ?? 32 91 ?? ?? ?? 00 88 54 24 ?? 0f b6 54 24 ?? 32 91 ?? ?? ?? 00 88 54 24 ?? 8b 54 24 ?? 81 c2 ?? ?? ?? 00 89 54 24 ?? 83 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GZK_2147943157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GZK!MTB"
        threat_id = "2147943157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 83 e0 ?? 8a 1c 10 8a c3 32 c1 32 44 24 ?? 88 04 39 83 f9 ?? ?? ?? 8d 41 ?? c0 e3 ?? 83 e0 ?? 8a 04 10 c0 e8 ?? 32 c3 32 c1 88 04 29 41 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PKV_2147943242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PKV!MTB"
        threat_id = "2147943242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c0 0f b6 c9 0f af c8 8a c1 c0 e8 04 32 04 13 32 c1 32 44 24 12 88 04 13 42 8b 44 24 ?? 40 89 54 24 14 89 44 24 28 81 fa 00 60 05 00 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZZA_2147943408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZZA!MTB"
        threat_id = "2147943408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 46 82 b7 6f 29 d9 11 d0 0b 2c 95 58 f3 dd 6c 4b a3 76 13 8c a7 e2 df 3a 24 fc 69 75 81 e7 a6 aa 97 a8 65 93 5d ec a0 23 61 25 0c 05 19 71 a6 c7 6c d7 99 17 db f5 38 1a 57 39 fe 13 a2 fa a6 10 40 00 04 81 14 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZZB_2147943409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZZB!MTB"
        threat_id = "2147943409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b6 0e 8d 51 f7 83 fa 17 77 08 0f a3 d0 73 03 46 eb ed 89 34 24 80 f9 7d 0f 85 cc 01 00 00 46 85 db 74 06 8b 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZZC_2147943410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZZC!MTB"
        threat_id = "2147943410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 45 d8 b1 3b f8 7f 3c eb d6 bc 73 5f 61 84 c2 65 d2 ab c3 b5 5d 60 1e 05 f6 6d 1d 07 4f 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZZD_2147943411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZZD!MTB"
        threat_id = "2147943411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 24 c3 78 8f 20 2f 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_ZZF_2147943412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.ZZF!MTB"
        threat_id = "2147943412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 38 d3 d9 03 d9 14 42 28 a8 f4 7b 00 77 b9 ae 50 60 fa 16 46 74 62 9d f5 ce d3 15 a8 c9 4c af 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GDI_2147944025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GDI!MTB"
        threat_id = "2147944025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c2 83 e0 ?? 8a 0c 28 32 cf 32 0e 88 0e}  //weight: 5, accuracy: Low
        $x_5_2 = {41 8a 0c 29 43 32 ca 89 5c 24 ?? 32 4c 24 ?? 8b d3 88 0c 30}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GDF_2147944135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GDF!MTB"
        threat_id = "2147944135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 d1 f7 d1 89 c6 21 ce 89 c7 31 d7 89 c1 01 f9 29 f1 21 d0 f7 d0 89 ca 31 c2 f7 d2 09 c1 21 d1 89 0c 24 8b 04 24 2d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLS_2147944621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLS!MTB"
        threat_id = "2147944621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c7 f7 75 ?? 8b 45 ?? 8a 04 02 32 c1 8b 4d ?? 32 01 8b 4d ?? 88 04 31 46 81 fb ?? ?? ?? ?? 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLS_2147944621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLS!MTB"
        threat_id = "2147944621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 44 34 ?? 56 50 e8 ?? ?? ?? ?? 83 c4 ?? 88 44 34 ?? 46 83 fe ?? 75}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b6 44 1c ?? 53 50 e8 ?? ?? ?? ?? 83 c4 ?? 88 44 1c ?? 43 83 fb ?? 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_IT_2147945072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.IT!MTB"
        threat_id = "2147945072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 81 ec ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 33 c9 c7 45 ?? ?? ?? ?? ?? b2 ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8b c1 66 c7 45 ?? ?? ?? 30 54 05 ?? 40 83 f8 ?? 73 ?? 8a 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GAD_2147945426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GAD!MTB"
        threat_id = "2147945426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c7 41 03 c5 99 f7 7c 24 ?? 8b 44 24 2c 8a 04 02 8b 54 24 ?? 32 c7 32 44 24 ?? 32 02 8b 54 24 ?? 88 04 17 47 8b c2 81 f9 07 01 00 00 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLN_2147945778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLN!MTB"
        threat_id = "2147945778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 f7 75 ?? c0 e1 ?? 32 cb c0 e1 ?? 8a 04 3a c0 e8 ?? 32 c8 8b 45 ?? 88 0c 03 43 81 fb ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLN_2147945778_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLN!MTB"
        threat_id = "2147945778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 85 54 ff ff ff 8b 8d 50 ff ff ff 8a 14 08 8b 85 54 ff ff ff 88 10 8b 85 54 ff ff ff 83 c0 01 89 85 54 ff ff ff 3b 85 4c ff ff ff 75}  //weight: 5, accuracy: High
        $x_5_2 = {c1 e8 05 01 c1 66 89 ca 8b 45 84 66 89 10 8b 45 94 03 45 94 89 45 94 8b 45 88 33 45 8c 89 45 8c eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_DFL_2147945826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.DFL!MTB"
        threat_id = "2147945826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 c8 89 44 24 04 8b 44 24 04 34 80 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 83 f0 ff 31 c9 29 c1 89 0c 24 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_WFL_2147945827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.WFL!MTB"
        threat_id = "2147945827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 0c 01 31 c1 81 f1 65 31 c8 04 89 4c 24 04 8b 44 24 04 04 0f 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 83 e8 ff 89 04 24 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLT_2147946180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLT!MTB"
        threat_id = "2147946180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b c8 c1 e2 ?? 8b 44 24 ?? 33 cd 33 6c 24 ?? 0b fa 89 4c 24 ?? 33 fe 8b 4c 24 ?? 83 e8 ?? 33 74 24 ?? 83 c1 ?? 83 6c 24 ?? ?? 89 4c 24 ?? 89 44 24 ?? 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGLT_2147946180_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGLT!MTB"
        threat_id = "2147946180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be f9 8d 5b ?? 69 f7 ?? ?? ?? ?? c1 ce ?? 8b d6 8b ce c1 ea ?? c1 e1 ?? 33 d1 8a 0b 33 d6 69 d2 ?? ?? ?? ?? 33 55 ?? c1 ca ?? 81 c2 ?? ?? ?? ?? 8d 14 92 33 d7 33 d0 89 55 ?? 84 c9 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPP_2147946351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPP!MTB"
        threat_id = "2147946351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 a0 05 00 00 10 00 00 00 4e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 24 03 00 00 00 b0 05 00 00 02 00 00 00 5e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 c0 05 00 00 02 00 00 00 60 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
        $x_1_2 = {20 20 20 00 20 20 20 20 00 80 05 00 00 10 00 00 00 4a 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 24 03 00 00 00 90 05 00 00 02 00 00 00 5a 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 a0 05 00 00 02 00 00 00 5c 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaStealer_RPP_2147946351_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPP!MTB"
        threat_id = "2147946351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 69 00 63 00 61 00 63 00 6c 00 73 00 [0-112] 2e 00 65 00 78 00 65 00 20 00 2f 00 69 00 6e 00 68 00 65 00 72 00 69 00 74 00 61 00 6e 00 63 00 65 00 3a 00 72 00 20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 3a 00 66 00 20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 20 00 65 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 72 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_JSM_2147946434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.JSM!MTB"
        threat_id = "2147946434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 0c 01 31 c8 35 5e fc 19 aa 89 44 24 04 8b 44 24 04 04 5a 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 89 c1 83 e1 01 89 c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_FAJ_2147947010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.FAJ!MTB"
        threat_id = "2147947010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 c4 32 1c 01 32 5d ff 88 1c 01 41 3b 4d 0c 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_FAK_2147947715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.FAK!MTB"
        threat_id = "2147947715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 c4 32 5d ff 8b 55 c8 30 18 8b 5d 14 8b 45 08 3b 4d 0c 72 a8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_LMX_2147947891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.LMX!MTB"
        threat_id = "2147947891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e2 14 87 f3 81 e0 b4 6c b8 c1 ff c9 75 c6 f7 d2 0b c4 b9 89 80 f6 70 03 f8 85 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_FAI_2147947931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.FAI!MTB"
        threat_id = "2147947931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 32 1c 10 8b 45 08 32 df 30 1f 8b 55 c8 3b 4d 0c 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_PGTP_2147947945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.PGTP!MTB"
        threat_id = "2147947945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 74 04 e6 e6 ea f1 38 e8 3c ?? 02 8d ?? ?? ?? ?? a1 ?? ?? ?? ?? 84 c0 74 ?? af e1 ?? 24 ?? 8b c7 48 80 38 ?? 5d e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_NR_2147949141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.NR!MTB"
        threat_id = "2147949141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe c9 8a 4d 02 81 c5 02 00 00 00 d2 ea}  //weight: 2, accuracy: High
        $x_1_2 = {32 d8 8d 44 04 0c 89 10 8d 64 24 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPQ_2147950708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPQ!MTB"
        threat_id = "2147950708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 69 00 63 00 61 00 63 00 6c 00 73 00 [0-112] 2e 00 65 00 78 00 65 00 20 00 2f 00 72 00 65 00 6d 00 6f 00 76 00 65 00 3a 00 64 00 20 00 65 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 20 00 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_RPR_2147950709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.RPR!MTB"
        threat_id = "2147950709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-executionpolicy bypass -command new-service -name downloaderservice -binarypathname" wide //weight: 10
        $x_1_2 = "-startuptype automatic" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GAPF_2147950953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GAPF!MTB"
        threat_id = "2147950953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {0f b6 4d ef 33 4d e0 8b 55 e4 88 0a 8b 45 f0 33 d2 b9 05 00 00 00 f7 f1 85 d2}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_GAPI_2147950954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.GAPI!MTB"
        threat_id = "2147950954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {31 c1 81 f1 ?? ?? ?? ?? 89 4c 24 04 8b 44 24 04 04 ?? 8b 4c 24 0c 8b 14 24 88 04 11}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealer_D_2147951231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealer.D!MTB"
        threat_id = "2147951231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 4f 02 2c 4c c5 6d ca 29 4e f9 ea 16 8e 1d 22 4e 06 fb 41 94 8a de fa}  //weight: 1, accuracy: High
        $x_1_2 = {28 00 4f 00 84 00 b2 00 12 00 31 00 e8 00 8c 00 13 00 65 00 fb 00 c9 00 54 00 d6 00 5b 00 5f 00 35 00 14 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

