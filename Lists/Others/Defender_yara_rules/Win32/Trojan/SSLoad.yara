rule Trojan_Win32_SSLoad_DA_2147908026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SSLoad.DA!MTB"
        threat_id = "2147908026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SSLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 f7 75 ?? 8a 44 15 ?? 30 81 ?? ?? ?? ?? 41 81 f9 d0 07 00 00 72 07 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 c7 45 [0-5] 8b c6 8d 0c 3e f7 75 ?? 03 d3 8a 44 15 ?? 8b 55 ?? 32 04 11 46 88 01 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SSLoad_ZZ_2147911677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SSLoad.ZZ!MTB"
        threat_id = "2147911677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SSLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 fc ff ff ff 8b 91 ?? ?? ?? ?? 33 54 08 ?? 89 54 0c ?? 83 c1 ?? 83 f9 ?? 72 ea}  //weight: 1, accuracy: Low
        $x_1_2 = "POST*/*HTTP/1.1Content-Type: application/json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

