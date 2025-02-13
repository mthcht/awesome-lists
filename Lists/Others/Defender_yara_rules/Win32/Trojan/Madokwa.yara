rule Trojan_Win32_Madokwa_CCIB_2147912714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Madokwa.CCIB!MTB"
        threat_id = "2147912714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Madokwa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 2b c8 03 cb 0f b6 44 0c ?? 8b ce 32 85 ?? ?? ?? ?? 88 47 ?? b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Madokwa_YAA_2147915336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Madokwa.YAA!MTB"
        threat_id = "2147915336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Madokwa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 d0 33 55 e6 89 4d e7 32 75 e4 0b 45 f1 89 55 eb}  //weight: 1, accuracy: High
        $x_10_2 = {8b 04 1f 33 45 f0 89 04 1e}  //weight: 10, accuracy: High
        $x_1_3 = {56 69 72 74 c7 45 90 01 01 75 61 6c 50 c7 45 90 01 01 72 6f 74 65 c7 45 90 01 01 63 74 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Madokwa_MKZ_2147915526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Madokwa.MKZ!MTB"
        threat_id = "2147915526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Madokwa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 8a 84 35 d8 fe ff ff 88 84 3d ?? ?? ?? ?? 88 8c 35 d8 fe ff ff 0f b6 84 3d ?? ?? ?? ?? 03 c2 8b 55 f8 0f b6 c0 8a 84 05 d8 fe ff ff 30 04 13 43 3b 5d dc 72 9e eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Madokwa_MKV_2147915527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Madokwa.MKV!MTB"
        threat_id = "2147915527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Madokwa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 2d 73 18 00 00 89 d0 03 85 a2 fe ff ff 89 8d ?? ?? ?? ?? 89 45 ab 8b 8d a3 fe ff ff 31 4d ee 0f b7 c0 8d 55 e6 2b 8d 2e ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {ba db 77 00 00 03 8d f0 fe ff ff 89 8d a7 fe ff ff 33 55 d6 89 8d 71 ff ff ff 8b 45 b4 b9 7d 08 00 00 3b 05 ?? ?? ?? ?? 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

