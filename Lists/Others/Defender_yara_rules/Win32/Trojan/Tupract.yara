rule Trojan_Win32_Tupract_A_2147682351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tupract.A"
        threat_id = "2147682351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tupract"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 75 70 25 78 25 78 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 56 ff d3 25 ff 00 00 00 c1 e0 10 83 c8 01 50 56 68 00 01 00 00 57 ff d5 68 c8 00 00 00 ff 15 ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

