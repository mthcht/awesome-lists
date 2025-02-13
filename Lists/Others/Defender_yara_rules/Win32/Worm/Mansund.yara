rule Worm_Win32_Mansund_A_2147611194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mansund.gen!A"
        threat_id = "2147611194"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansund"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 45 d4 88 04 31 8b 4d d0 83 c1 01 0f 80 e4 00 00 00 89 4d d0 b8 02 00 00 00 03 c3 0f 80 d4 00 00 00 8b d8 33 f6 e9 42 fd ff ff}  //weight: 5, accuracy: High
        $x_1_2 = {5c 00 53 00 6f 00 75 00 6e 00 64 00 4d 00 61 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 76 00 63 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "guanshadu" ascii //weight: 1
        $x_1_5 = {63 68 75 61 6e 62 6f 00}  //weight: 1, accuracy: High
        $x_1_6 = "cmd.exe /c net stop wscsvc" wide //weight: 1
        $x_1_7 = {6e 00 6f 00 74 00 65 00 70 00 64 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

