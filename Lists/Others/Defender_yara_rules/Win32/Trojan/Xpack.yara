rule Trojan_Win32_Xpack_B_2147837853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xpack.B!MTB"
        threat_id = "2147837853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "One8Neo" ascii //weight: 2
        $x_2_2 = "Two8Neo" ascii //weight: 2
        $x_2_3 = "Thr8Neo" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xpack_C_2147838020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xpack.C!MTB"
        threat_id = "2147838020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ErrhdtPiu" ascii //weight: 2
        $x_2_2 = "SdfgLjhgf" ascii //weight: 2
        $x_2_3 = "WergVghj" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xpack_CLL_2147838782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xpack.CLL!MTB"
        threat_id = "2147838782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 06 83 c6 01 68 ?? ?? ?? ?? 83 c4 ?? 89 c0 32 02 89 c0 47 88 47 ff 68 ?? ?? ?? ?? 83 c4 ?? 42 83 e9 ?? 83 ec ?? c7 04 24 ?? ?? ?? ?? 83 c4 ?? 83 ec ?? c7 04 24 ?? ?? ?? ?? 83 c4 ?? 85 c9 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xpack_RPY_2147889008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xpack.RPY!MTB"
        threat_id = "2147889008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 b9 0a 00 00 00 8b 04 9e f7 f1 88 15 ?? ?? ?? ?? 89 04 9f 4b 59 49 75 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xpack_RPY_2147889008_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xpack.RPY!MTB"
        threat_id = "2147889008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 81 c2 ff 00 00 00 89 c6 81 e6 1f 00 00 00 8a 1c 31 8b 4d f0 8a 3c 01 28 df 88 3c 01 8b 45 f4 39 c2 89 55 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xpack_RPZ_2147894767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xpack.RPZ!MTB"
        threat_id = "2147894767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 0c 89 e6 89 46 04 c7 46 08 04 01 00 00 c7 06 00 00 00 00 8b 35 ?? ?? ?? ?? 89 85 b8 fe ff ff 89 8d b4 fe ff ff ff d6 83 ec 08 89 e1 8b 95 f0 fe ff ff 89 51 04 8b b5 b8 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xpack_GNF_2147894984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xpack.GNF!MTB"
        threat_id = "2147894984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 53 8b f1 66 83 fa 10 ?? ?? 33 d2 8a 18 8b ca 81 e1 ?? ?? ?? ?? 8a 4c 4c 0c 32 d9 42 88 18 40 4e}  //weight: 10, accuracy: Low
        $x_1_2 = "bs360.co.cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

