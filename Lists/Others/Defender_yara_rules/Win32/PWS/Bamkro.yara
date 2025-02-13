rule PWS_Win32_Bamkro_A_2147697308_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bamkro.A"
        threat_id = "2147697308"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamkro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kurobam19.ml/user.php" ascii //weight: 2
        $x_2_2 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 25 00 73 00 5c 00 25 00 73 00 00 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 64 00 61 00 74 00 00 00 66 00 6c 00 61 00 73 00 68 00 70 00 6c 00 61 00 79 00 65 00 72 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: High
        $x_1_3 = "%s\\Microsoft\\Network\\svchost.exe" ascii //weight: 1
        $x_1_4 = "GET /view/game/game.asp?type=Baduki" ascii //weight: 1
        $x_1_5 = "Bank of America log-in" ascii //weight: 1
        $x_1_6 = "www.goo87.comwww.omc31.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

