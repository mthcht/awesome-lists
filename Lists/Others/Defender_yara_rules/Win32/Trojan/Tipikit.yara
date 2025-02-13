rule Trojan_Win32_Tipikit_A_2147603222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tipikit.A"
        threat_id = "2147603222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tipikit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0c 47 80 2e 7b 8a 06 88 87 ?? ?? 40 00 80 3d ?? ?? 43 00 0a 75 11 80 fb 14 75 0c 80 3e 1e 75 07 c6 05 22 76 43 00 01 b8 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

