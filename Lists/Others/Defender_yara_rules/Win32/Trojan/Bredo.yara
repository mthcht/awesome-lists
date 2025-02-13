rule Trojan_Win32_Bredo_PA_2147787566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bredo.PA!MTB"
        threat_id = "2147787566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bredo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 10 00 b9 ?? ?? ?? ?? 33 c0 8a 90 ?? ?? ?? ?? 32 d1 41 81 e1 ff 00 00 80 88 54 04 ?? 79 ?? 49 81 c9 00 ff ff ff 41 40 83 f8 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "hahaha.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

