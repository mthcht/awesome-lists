rule Trojan_Win32_Vreikstadi_A_2147710524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vreikstadi.A"
        threat_id = "2147710524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vreikstadi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 05 80 35 35 c7 40 04 34 3b 0d 7b c7 40 08 04 31 17 68}  //weight: 1, accuracy: High
        $x_1_2 = {c7 40 1c 05 31 09 68 c7 40 20 17 35 34 3b c7 40 24 66 7b 61 31}  //weight: 1, accuracy: High
        $x_1_3 = {c7 40 74 c7 78 61 31 c7 40 78 ec 51 11 2b c7 40 7c 5e 07 8e e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

