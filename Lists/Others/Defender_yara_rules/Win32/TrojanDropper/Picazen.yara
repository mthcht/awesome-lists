rule TrojanDropper_Win32_Picazen_A_2147621285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Picazen.gen!A"
        threat_id = "2147621285"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Picazen"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 84 24 10 01 00 00 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 50 ff 15 20 10 40 00 8d 4c 24 08 6a 00}  //weight: 2, accuracy: High
        $x_2_2 = {c6 44 24 10 50 c6 44 24 11 4b c6 44 24 12 03 c6 44 24 13 04}  //weight: 2, accuracy: High
        $x_1_3 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 68 00 66 00 62 00 6c 00 64 00 64 00 65 00 6c 00 2e 00 62 00 61 00 74 00 [0-6] 53 00 59 00 53 00 54 00 45 00 4d 00 52 00 4f 00 4f 00 54 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6f 00 70 00 65 00 6e 00 [0-6] 25 00 73 00 5c 00 25 00 73 00 [0-4] 5c 00 [0-4] 54 00 45 00 4d 00 50 00}  //weight: 1, accuracy: Low
        $x_1_5 = "if exist \"%s\" goto repeat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

