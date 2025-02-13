rule Trojan_Win32_Gapined_DSK_2147749987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gapined.DSK!MTB"
        threat_id = "2147749987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gapined"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 30 84 05 f0 fe ff ff 40 3b c7 7c 06 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 54 24 10 8b c7 c1 e8 05 03 44 24 ?? 03 cb 03 d7 33 ca 04 00 8b 4c 24}  //weight: 2, accuracy: Low
        $x_2_3 = {8b c1 c1 e8 02 24 3f c0 e1 06 0a c1 88 82 ?? ?? ?? ?? 83 c6 02 42 83 fe 1e 0f 82}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 44 24 14 8a 0c 50 8a 14 1f 32 d1 88 14 1f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

