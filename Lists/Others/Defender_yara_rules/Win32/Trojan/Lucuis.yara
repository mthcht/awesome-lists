rule Trojan_Win32_Lucuis_A_2147652821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lucuis.A"
        threat_id = "2147652821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lucuis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 55 4c 5f 46 49 4c 45 5f 4f 4b 00}  //weight: 1, accuracy: High
        $x_1_2 = "LURKER_" ascii //weight: 1
        $x_1_3 = {3d 4d 46 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {3d 44 44 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

