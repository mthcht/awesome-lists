rule Trojan_Win32_Symmi_SIBA_2147807753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Symmi.SIBA!MTB"
        threat_id = "2147807753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Symmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TCPView" wide //weight: 1
        $x_1_2 = "ProcessHacker" wide //weight: 1
        $x_1_3 = "Process Monitor" wide //weight: 1
        $x_1_4 = "OLLYDBG" wide //weight: 1
        $x_1_5 = "PortmonClass" wide //weight: 1
        $x_1_6 = "taskmgr.exe" wide //weight: 1
        $x_20_7 = {83 c0 01 89 45 ?? 83 7d 00 04 0f 8d ?? ?? ?? ?? c7 45 ?? 00 00 00 00 83 7d 03 04 7d ?? 8b 55 00 c1 e2 04 8b 45 0c 8b 4d 03 8b 75 10 d9 04 10 d8 0c 8e 8b 55 00 c1 e2 04 8b 45 0c 8b 4d 03 8b 75 10 d9 44 10 04 d8 4c 8e 10 de c1 8b 55 00 c1 e2 04 8b 45 0c 8b 4d 03 8b 75 10 d9 44 10 08 d8 4c 8e 20 de c1 8b 55 00 c1 e2 04 8b 45 0c 8b 4d 03 8b 75 10 d9 44 10 0c d8 4c 8e 30 de c1 8b 55 00 c1 e2 04 8b 45 08 03 c2 8b 4d 03 d9 1c 88 8b 4d 03 83 c1 01 89 4d 03 83 7d 03 04 8b 45 00 83 c0 01 89 45 00 83 7d 00 04 0f 8d}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Symmi_CCAP_2147890129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Symmi.CCAP!MTB"
        threat_id = "2147890129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Symmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8a 88 88 58 5d 00 88 4d ef 0f b6 45 ef 83 f0 ?? 88 45 ef 0f b6 45 ef f7 d8 88 45 ef 0f b6 45 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Symmi_GMR_2147893069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Symmi.GMR!MTB"
        threat_id = "2147893069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Symmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FGHN6546FGX546H5CJ54H6G5F4656XGF" ascii //weight: 1
        $x_1_2 = "K68D4G684G6C5F465F4D654F6X54F6D5F46XD5Z4S6F54F65ZDF4S654DZ64SD" ascii //weight: 1
        $x_1_3 = "asdasdkjhxzciuaysfoiqeuflk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Symmi_GNM_2147919600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Symmi.GNM!MTB"
        threat_id = "2147919600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Symmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {22 51 bc 24 56 60 30 3c bc 41 b3 ff c3}  //weight: 10, accuracy: High
        $x_10_2 = {01 31 08 5f 0f 09 63 30 1d 81 16 c3 df 37 30 34 36 2b 4e 82 ed 88 b1}  //weight: 10, accuracy: High
        $x_1_3 = "or'6lass HierJyo" ascii //weight: 1
        $x_1_4 = "rvy8SizeofResourcLo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Symmi_MBXS_2147919873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Symmi.MBXS!MTB"
        threat_id = "2147919873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Symmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 2e 64 6c 6c 00 44 6c 6c 43 6d 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Symmi_GTZ_2147926003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Symmi.GTZ!MTB"
        threat_id = "2147926003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Symmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 33 2e 37 2e 30 00 9c 66 51 8d 64 24}  //weight: 5, accuracy: High
        $x_5_2 = {54 33 ce 67 f7 83 ?? ?? ?? ?? ?? ?? 09 0f 31 8b ?? ?? ?? ?? 8f 44 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

