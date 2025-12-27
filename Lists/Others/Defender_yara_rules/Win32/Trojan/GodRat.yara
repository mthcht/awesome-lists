rule Trojan_Win32_GodRat_C_2147949702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GodRat.C!MTB"
        threat_id = "2147949702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GodRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c}  //weight: 3, accuracy: Low
        $x_2_2 = {8b f8 85 ff 0f 84 ?? ?? ?? ?? 8b cf 85 ?? 74 ?? 8b 55 ?? 2b d7 0f 1f 80 00 00 00 00 8a 04 0a 8d 49 01 88 41 ff 83 ee 01 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

