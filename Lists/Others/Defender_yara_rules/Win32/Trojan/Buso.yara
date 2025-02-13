rule Trojan_Win32_Buso_A_2147599386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buso.A"
        threat_id = "2147599386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 0e c6 04 37 00 eb 08 8b 45 08 4e 03 c6 30 18 85 f6 75 f4 39 7d 08 75 10 8d 45 fc 50 ff 75 0c}  //weight: 2, accuracy: High
        $x_1_2 = {74 72 56 88 18 ff 15 ?? ?? ?? ?? 38 1e 8b f8 8b c6 74 08 80 30 ?? 40 38 18 75 f8 8d 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

