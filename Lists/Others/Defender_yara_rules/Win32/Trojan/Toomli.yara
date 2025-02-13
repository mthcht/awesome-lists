rule Trojan_Win32_Toomli_A_2147734225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Toomli.A!dha"
        threat_id = "2147734225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Toomli"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3f 25 73 3d 25 64 25 64 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 74 61 72 74 32 77 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 78 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 4e 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

