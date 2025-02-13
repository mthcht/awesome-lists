rule Trojan_Win32_Taidoor_C_2147761251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taidoor.C!dha"
        threat_id = "2147761251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taidoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {4d 65 6d 6f 72 79 4c 6f 61 64 2e 64 6c 6c 00 4d 79 53 74 61 72 74 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

