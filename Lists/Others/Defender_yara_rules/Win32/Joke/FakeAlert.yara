rule Joke_Win32_FakeAlert_A_2147611518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Joke:Win32/FakeAlert.gen!A"
        threat_id = "2147611518"
        type = "Joke"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAlert"
        severity = "Mid"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 60 31 00 46 6f 72 6d 31 00 45 76 69 6c 47 75 79 00 52 65 73 6f 75 72 63 65 73 00 45 76 69 6c}  //weight: 1, accuracy: High
        $x_1_2 = {64 6f 77 6e 00 45 78 69 74 00 45 76 69 6c 47 75}  //weight: 1, accuracy: High
        $x_1_3 = {32 30 30 38 00 00 0c 01 00 07 45 76 69 6c 47 75}  //weight: 1, accuracy: High
        $x_1_4 = "Guy\\EvilGuy\\obj\\Release\\EvilGuy." ascii //weight: 1
        $x_1_5 = {00 75 00 20 00 67 00 6f 00 74 00 20 00 61 00 20 00 76 00 69 00 72 00 75 00 73 00 21 00 20 00 48 00 6f 00 77 00 20 00 74 00 68 00 65 00 20 00 68}  //weight: 1, accuracy: High
        $x_1_6 = {00 75 00 79 00 20 00 41 00 20 00 4d 00 61 00 63 00 21 00 00 23 45 00 76 00 69 00 6c 00 47 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

