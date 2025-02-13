rule Trojan_Win32_Ogpha_A_2147611127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ogpha.A"
        threat_id = "2147611127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogpha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rd/mydd.php?" ascii //weight: 1
        $x_1_2 = {6c 70 47 65 74 64 41 54 41 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {38 39 2e 31 34 39 2e 32 32 36 2e 35 34 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 66 32 34 61 31 37 61 61 34 66 38 33 66 36 30 61 64 66 63 30 61 63 39 35 64 39 34 33 32 64 36 00}  //weight: 1, accuracy: High
        $x_2_5 = {83 7d fc 14 7d 31 83 7d f8 0f 7d 2b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ogpha_B_2147611157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ogpha.B"
        threat_id = "2147611157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogpha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rd/fxto1.php" ascii //weight: 1
        $x_1_2 = {38 39 2e 31 34 39 2e 32 32 36 2e 35 34 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 36 32 36 33 34 31 39 63 31 63 66 64 63 30 64 36 65 62 33 62 38 64 35 37 36 64 63 64 32 66 32 00}  //weight: 1, accuracy: High
        $x_2_4 = {83 7d fc 05 7d 31 83 7d f8 05 7d 2b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

