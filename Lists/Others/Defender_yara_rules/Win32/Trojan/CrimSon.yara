rule Trojan_Win32_CrimSon_J_2147753064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrimSon.J!ibt"
        threat_id = "2147753064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrimSon"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AKRPCON" ascii //weight: 1
        $x_1_2 = "dbsrualbmloadMe" ascii //weight: 1
        $x_1_3 = {70 17 8d 05 00 00 01 13 ?? 11 ?? 16 06 a2 00 11 ?? 14 14 14 28 ?? 00 00 0a 28 0a 00 00 0a 13}  //weight: 1, accuracy: Low
        $x_1_4 = {02 72 b9 00 00 70 17 8d ?? 00 00 01 0a 06 16 1f 7c 9d 06 6f 61 00 00 0a 16 9a 7d 0d 00 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

