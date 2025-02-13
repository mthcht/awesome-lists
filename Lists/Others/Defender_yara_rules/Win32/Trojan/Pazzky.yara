rule Trojan_Win32_Pazzky_A_2147649424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pazzky.A"
        threat_id = "2147649424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pazzky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ".php?pazz=tazmaniakasparskyfromwhere&&id=" ascii //weight: 5
        $x_1_2 = {3a 5c 43 6f 6c 64 70 6c 61 79 5c 56 69 76 61 20 6c 61 20 76 69 64 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 69 6e 64 6f 77 73 6c 6f 67 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "localhost/kasparsky/" ascii //weight: 1
        $x_1_5 = {26 26 4c 6f 63 61 6c 69 73 61 74 69 6f 6e 5f 67 65 6f 67 72 61 70 68 69 71 75 65 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {41 6e 74 ef 76 69 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {26 26 55 72 6c 5f 69 6d 61 67 65 5f 64 72 61 70 65 61 75 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {26 26 41 64 72 65 73 73 65 5f 49 70 3d 00}  //weight: 1, accuracy: High
        $x_1_9 = {69 70 6c 6f 63 61 74 69 6f 6e 74 6f 6f 6c 73 2e 63 6f 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

