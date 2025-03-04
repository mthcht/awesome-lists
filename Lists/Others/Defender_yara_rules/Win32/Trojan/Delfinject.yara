rule Trojan_Win32_Delfinject_AD_2147797493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.AD!MTB"
        threat_id = "2147797493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pmNotCopy" ascii //weight: 3
        $x_3_2 = "qjhthhpkjqkmpilr" ascii //weight: 3
        $x_3_3 = "WinHelpViewer" ascii //weight: 3
        $x_3_4 = "UrlMon" ascii //weight: 3
        $x_3_5 = "mkuomto" ascii //weight: 3
        $x_3_6 = "kipihph" ascii //weight: 3
        $x_3_7 = "hmwhnpm" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_AD_2147797493_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.AD!MTB"
        threat_id = "2147797493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Glyph.Data" ascii //weight: 3
        $x_3_2 = "WinHttpCrackUrl" ascii //weight: 3
        $x_3_3 = "LockResource" ascii //weight: 3
        $x_3_4 = {5a 00 5f 00 57 00 45 00 5a}  //weight: 3, accuracy: High
        $x_3_5 = "VMmUSWUSWVMma" ascii //weight: 3
        $x_3_6 = "GetKeyboardType" ascii //weight: 3
        $x_3_7 = "CopyEnhMetaFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_AD_2147797493_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.AD!MTB"
        threat_id = "2147797493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Magellan MSWHEEL" ascii //weight: 3
        $x_3_2 = "lld.isma\\23metsyS\\swodniW\\:C" ascii //weight: 3
        $x_3_3 = "KillTimer" ascii //weight: 3
        $x_3_4 = "MFCreate3GPMediaSink" ascii //weight: 3
        $x_3_5 = "WinHttpCheckPlatform" ascii //weight: 3
        $x_3_6 = "ilia@valley.ru" ascii //weight: 3
        $x_3_7 = "pk|SIpQHhNBD" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_RM_2147797495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.RM!MTB"
        threat_id = "2147797495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 c4 f9 74 ?? 8b 15 ?? ?? ?? ?? 8b 12 03 15 ?? ?? ?? ?? 66 25 ff 0f 0f b7 c0 03 d0 a1 ?? ?? ?? ?? 01 02 42 8d 14 1b 83 03 02 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_RM_2147797495_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.RM!MTB"
        threat_id = "2147797495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 77 01 00 00 8b 01 0f b7 18 f6 c7 f0 74 ?? a1 ?? ?? ?? ?? 8b 00 03 05 ?? ?? ?? ?? 66 81 e3 ff 0f 0f b7 db 03 c3 8b 1d ?? ?? ?? ?? 01 18 83 01 02 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_RW_2147797591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.RW!MTB"
        threat_id = "2147797591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 10 00 00 a1 ?? ?? ?? ?? 50 8b 06 8d 04 80 8b 15 ?? ?? ?? ?? 8b 44 c2 ?? 03 05 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 c4 f0 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b 03 1d ?? ?? ?? ?? 66 25 ff 0f 0f b7 c0 03 d8 a1 ?? ?? ?? ?? 01 03 83 01 02 ff 05 ?? ?? ?? ?? 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_AC_2147798145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.AC!MTB"
        threat_id = "2147798145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WndProcPtr%.8X%.8X" ascii //weight: 3
        $x_3_2 = "vcltest3.dll" ascii //weight: 3
        $x_3_3 = "BKbhTb~XBK!" ascii //weight: 3
        $x_3_4 = "ddhhllppttttxxxx" ascii //weight: 3
        $x_3_5 = "KillTimer" ascii //weight: 3
        $x_3_6 = "WinHttpCrackUrl" ascii //weight: 3
        $x_3_7 = "Delphi.Ru" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_RWB_2147811338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.RWB!MTB"
        threat_id = "2147811338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 c7 f0 74 ?? 8b 45 ?? 8b 40 ?? 8b 75 ?? 8b 76 ?? 03 06 66 81 e3 ff 0f 0f b7 db 03 c3 8b 5d ?? 8b 5b ?? 01 18 83 01 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_RTA_2147813278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.RTA!MTB"
        threat_id = "2147813278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 f7 c7 00 f9 74 ?? 8b 45 ?? 8b 40 ?? 8b 55 ?? 8b 52 ?? 03 02 66 81 e7 ff 0f 0f b7 d7 03 c2 8b 55 ?? 8b 52 ?? 01 10 92 92 29 c8 29 c8 8d 0c 13 83 06 02 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delfinject_RMA_2147816196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfinject.RMA!MTB"
        threat_id = "2147816196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 ee 0b 00 00 8d 04 08 50 58 6a 04 68 00 10 00 00 a1 ?? ?? ?? ?? 50 8b 06 8d 04 80 8b 15 ?? ?? ?? ?? 8b 44 c2 ?? 03 05 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8d 8b ?? ?? ?? ?? 05 ee 0b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

