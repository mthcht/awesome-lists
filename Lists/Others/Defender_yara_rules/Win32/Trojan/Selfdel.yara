rule Trojan_Win32_Selfdel_B_2147697018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Selfdel.B"
        threat_id = "2147697018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Selfdel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" wide //weight: 2
        $x_1_2 = {ff 75 0c ff d7 59 84 c0 59 74 47 8d 85 c4 fd ff ff 50 53 53 6a 28 53 e8}  //weight: 1, accuracy: High
        $x_1_3 = {ff 75 0c ff d7 59 84 c0 59 0f 85 c2 01 00 00 68}  //weight: 1, accuracy: High
        $x_1_4 = {ff d6 59 84 c0 59 75 37 8d 45 d4 50 68}  //weight: 1, accuracy: High
        $x_1_5 = {39 9d 6c ff ff ff 0f 84 e8 00 00 00 39 9d 5c ff ff ff 0f 84 dc 00 00 00 38 5d f2 75 0c 38 5d f3 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

