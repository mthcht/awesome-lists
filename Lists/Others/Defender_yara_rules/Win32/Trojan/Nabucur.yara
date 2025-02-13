rule Trojan_Win32_Nabucur_AA_2147742608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nabucur.AA"
        threat_id = "2147742608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nabucur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 68 05 30 40 00 68 00 30 40 00 6a 00 e8 17 04 00 00 6a 00 e8 16 04 00 00 e8 17 04 00 00 e8 1e 04 00 00 e8 13 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

