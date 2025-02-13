rule Trojan_Win32_Parchood_A_2147641316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Parchood.A"
        threat_id = "2147641316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Parchood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 34 06 00 00 (ff|8b 1a) 33 c3 83 e1 01 33 04 8d ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {10 ab 49 75 f6 c7 05 00 ?? 00 10 70 02 00 00 c2 04 00 05 00 f7 25 04 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Parchood_B_2147647956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Parchood.B"
        threat_id = "2147647956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Parchood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 f8 d3 c3 09 00 5f eb 03 80 e9 20 80 f9 20}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 eb 06 04 34 00 ff ff 53 50 68 02 00 00 80 ff 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

