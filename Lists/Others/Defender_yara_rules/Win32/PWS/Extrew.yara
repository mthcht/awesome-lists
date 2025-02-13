rule PWS_Win32_Extrew_A_2147627979_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Extrew.A"
        threat_id = "2147627979"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Extrew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 44 24 ?? d4 07 66 c7 44 24 ?? 08 00 66 c7 44 24 ?? 11 00 66 c7 44 24 ?? 14 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 3d 01 00 ff d0 83 c4 08 3d 22 3d 01 00 7c 26}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 25 64 2e 57 57 57 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Extrew_B_2147627980_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Extrew.B"
        threat_id = "2147627980"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Extrew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 77 75 3a 80 bd ?? ?? ff ff 6f 75 31 80 bd ?? ?? ff ff 77 75 28 80 bd ?? ?? ff ff 2e 75 1f 80 bd ?? ?? ff ff 65}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? 8b 75 ?? 81 fe 00 00 40 00 72 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

