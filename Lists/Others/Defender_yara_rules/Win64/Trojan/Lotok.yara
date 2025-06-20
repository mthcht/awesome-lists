rule Trojan_Win64_Lotok_GPC_2147902629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.GPC!MTB"
        threat_id = "2147902629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 b9 00 30 00 00 48 8b 4c 24 50 48 03 df c7 44 24 20 40 00 00 00 44 8b 43 50 8b 53 34 ff 15 ?? ?? ?? ?? 4c 8b f0 48 85 c0}  //weight: 5, accuracy: Low
        $x_5_2 = {48 03 c6 4c 89 6c 24 20 44 8b 44 18 2c 8b 54 18 24 4c 03 c1 48 8b 4c 24 50 49 03 d6 44 8b 4c 18 28}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_RW_2147912063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.RW!MTB"
        threat_id = "2147912063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 08 44 8b cb 41 81 f0 6e 74 65 6c 41 81 f0 6e 74 65 6c 48 83 c0 08}  //weight: 1, accuracy: High
        $x_1_2 = "HookWnd64.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_RZ_2147912507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.RZ!MTB"
        threat_id = "2147912507"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 c1 78 56 34 12 48 ff c9 4d 33 c9 48 8b c1 75 f5 48 33 c0 48 8b c3 48 03 c2 90 90 90 49 ff ca 4d 33 db 75 da 48 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_DA_2147924483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.DA!MTB"
        threat_id = "2147924483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Potential sandbox environment detected" ascii //weight: 10
        $x_1_2 = "Failed to get executable name" ascii //weight: 1
        $x_10_3 = "MicrosoftEdgeUpdate.exe" ascii //weight: 10
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "PeLoaderErr" ascii //weight: 1
        $x_1_6 = "PeParserErr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_D_2147925891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.D!MTB"
        threat_id = "2147925891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 48 81 ec a0 00 00 00 48 c7 c1 00 00 00 00 48 c7 c2 ?? ac 00 00 49 c7 c0 00 10 00 00 4c 8d 49 40}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_GTM_2147926237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.GTM!MTB"
        threat_id = "2147926237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 48 89 e5 48 83 ec ?? 85 c0 41 81 f0 ?? ?? ?? ?? b9 ?? ?? ?? ?? 41 81 f1 ?? ?? ?? ?? 41 81 f0 ?? ?? ?? ?? 48 83 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_NIT_2147928893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.NIT!MTB"
        threat_id = "2147928893"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ntg.dat" ascii //weight: 2
        $x_2_2 = "sbs.dat" ascii //weight: 2
        $x_2_3 = "UnpackDDElParam" ascii //weight: 2
        $x_2_4 = "GdipCreateBitmapFromHBITMAP" ascii //weight: 2
        $x_1_5 = "DeactivateActCtx" ascii //weight: 1
        $x_1_6 = "WINSPOOL.DRV" ascii //weight: 1
        $x_1_7 = "AVCDownloader" ascii //weight: 1
        $x_1_8 = "CryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_PNT_2147935007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.PNT!MTB"
        threat_id = "2147935007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 0f b6 01 49 ff c0 49 ff c1 41 30 40 ff 49 83 ea 01 75}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lotok_NC_2147944295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lotok.NC!MTB"
        threat_id = "2147944295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "8154938939:AAFv22mAUWYk9yAvodHUNhDObC1ybZkKXAQ" ascii //weight: 2
        $x_1_2 = "curl -s ifconfig.me > ip.txt" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "MyAutoStartApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

