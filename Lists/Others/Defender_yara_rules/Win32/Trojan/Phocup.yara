rule Trojan_Win32_Phocup_A_2147773783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phocup.A!dha"
        threat_id = "2147773783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phocup"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "54.36.19.174" wide //weight: 1
        $x_1_2 = "NTQuMzYuMTkuMTc0" wide //weight: 1
        $x_1_3 = "U0LjM2LjE5LjE3N" wide //weight: 1
        $x_1_4 = "1NC4zNi4xOS4xNz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

