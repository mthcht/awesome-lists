rule TrojanDownloader_Win32_Remandson_A_2147649803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Remandson.A"
        threat_id = "2147649803"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Remandson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 03 6a 04 8d 8e 9c 2a 00 00 51 c6 44 24}  //weight: 2, accuracy: High
        $x_2_2 = {83 c7 01 3b fd 7c f5 85 f6 75 04 33 c0 eb 12 8b c6 8d 50 01}  //weight: 2, accuracy: High
        $x_1_3 = {8d 44 24 4c 83 c4 04 8d bb a8 2a 00 00 8d 68 01 8a 08 83 c0 01 84 c9 75 f7 2b c5}  //weight: 1, accuracy: High
        $x_1_4 = "MS5jby5rci9tb2R1" ascii //weight: 1
        $x_1_5 = "1.co.kr/m" ascii //weight: 1
        $x_1_6 = "aHR0cDovLzExMTAwMC5jby5rci9jb3Vu" ascii //weight: 1
        $x_1_7 = "111000.co.kr/coun" ascii //weight: 1
        $x_1_8 = "ci9jb3VudC9pbnNlcnQucGhwP3Bp" ascii //weight: 1
        $x_1_9 = "unt/insert.php?pid" ascii //weight: 1
        $x_1_10 = {5b 43 4f 55 4e 54 5d 00 69 65 78 70 6c 6f 72 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

