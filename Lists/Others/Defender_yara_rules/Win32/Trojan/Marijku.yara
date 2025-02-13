rule Trojan_Win32_Marijku_A_2147618431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Marijku.A"
        threat_id = "2147618431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Marijku"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 78 0c 64 26 08 00 74 09 c7 46 18 0d 00 00 c0 eb 22 57 68 ?? ?? 01 00 57 57 57 68 ff 03 1f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 1b 8d 7e 38 59 b8 ?? ?? 01 00 f3 ab c7 46 34 ?? ?? 01 00 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Marijku_A_2147618431_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Marijku.A"
        threat_id = "2147618431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Marijku"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 64 26 08 00 8b 4d f0 51 ff 15 ?? ?? ?? 10 89 45 a8 8b 55 f0 52 ff 15 ?? ?? ?? 10 8b 4d f4 64 89 0d 00 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "/para.htm?rnd=%d" ascii //weight: 1
        $x_1_3 = {61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

