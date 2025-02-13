rule PWS_Win32_Axespec_B_2147632522_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Axespec.B"
        threat_id = "2147632522"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Axespec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 10 46 38 9e ?? ?? ?? ?? 0f 44 f3 38 18 74 03 40 eb e7 83 c1 04 83 f9 ?? 72 d9 55 57 33 ed}  //weight: 10, accuracy: Low
        $x_10_2 = "http://musiceng.ru/music/forum/index1.php" wide //weight: 10
        $x_1_3 = "WINNT_7467B293DE9D" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Axespec_A_2147636065_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Axespec.A"
        threat_id = "2147636065"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Axespec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {be 00 02 00 00 eb 1c 39 7d fc 76 2f 6a 1e ff 75 fc 8d 85 ?? ?? ff ff 50 ff 75 08 e8 ?? ?? ff ff}  //weight: 3, accuracy: Low
        $x_1_2 = "<div class=\"f1\"><a href=\"/%S\">[%S]</a></div>" ascii //weight: 1
        $x_1_3 = "<div class=\"f2\"><a href=\"/%S\">%S</a></div>" ascii //weight: 1
        $x_1_4 = "Content-Type: application/winrar" ascii //weight: 1
        $x_1_5 = "PROCESS_MT_" ascii //weight: 1
        $x_1_6 = "PROCESS_ET_" ascii //weight: 1
        $x_1_7 = "cmd.exe /c \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Axespec_A_2147636065_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Axespec.A"
        threat_id = "2147636065"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Axespec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 64 69 76 20 63 6c 61 73 73 3d 22 66 31 22 3e 3c 61 20 68 72 65 66 3d 22 2f 25 53 22 3e 5b 25 53 5d 3c 2f 61 3e 3c 2f 64 69 76 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {3c 64 69 76 20 63 6c 61 73 73 3d 22 66 32 22 3e 3c 61 20 68 72 65 66 3d 22 2f 25 53 22 3e 25 53 3c 2f 61 3e 3c 2f 64 69 76 3e 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 77 69 6e 72 61 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 52 00 4f 00 43 00 45 00 53 00 53 00 5f 00 4d 00 54 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 00 52 00 4f 00 43 00 45 00 53 00 53 00 5f 00 45 00 54 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 43 00 65 00 6e 00 74 00 65 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 00 76 00 72 00 77 00 73 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

