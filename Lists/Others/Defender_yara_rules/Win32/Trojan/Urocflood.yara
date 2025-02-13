rule Trojan_Win32_Urocflood_A_2147712501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urocflood.A"
        threat_id = "2147712501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urocflood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 69 2e 25 69 2e 25 69 2e 25 69 00}  //weight: 1, accuracy: High
        $x_2_2 = {68 39 05 00 00 66 89 46 02 ff ?? ?? ?? ?? 00 68 39 05 00 00 89 46 04 ff ?? ?? ?? ?? 00 68 39 05 00 00 89 46 08 66 c7 46 0c 50 02 ff ?? ?? ?? ?? 00 8b 55 08 66 89 46 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

