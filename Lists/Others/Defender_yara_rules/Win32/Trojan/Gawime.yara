rule Trojan_Win32_Gawime_A_2147653679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gawime.A"
        threat_id = "2147653679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gawime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 c4 18 84 c0 5e 74 19 ff 75 14 ff 75 10 ff 75 0c ff 75 08 e8}  //weight: 3, accuracy: High
        $x_1_2 = {43 3a 5c 74 6d 70 2e 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6c 6c 52 75 6e 69 6e 67 00 00 00 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 6c 6e 6b 00 00 00 00 5c 00 00 00 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 00 00 00 3a 6b 69 6c 6c}  //weight: 1, accuracy: High
        $x_1_6 = "if %errorlevel%==1 (goto kill)" ascii //weight: 1
        $x_1_7 = "tasklist |find" ascii //weight: 1
        $x_1_8 = "WinGame_" ascii //weight: 1
        $x_1_9 = {5c 38 37 6f 6d 33 73 32 75 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 70 6f 62 61 6f 5f 64 68 78 79 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

