rule Trojan_Win32_Torug_A_2147637266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Torug.A"
        threat_id = "2147637266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Torug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 2d 80 b4 05 ?? ?? ?? ?? 09 40 83 f8 05 72 f2 57 57 57 56 ff 15 ?? ?? ?? 00 57 8d 45 ?? 50 6a 05 8d 85 00 50 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

