rule Spammer_WinNT_Nuwar_A_2147595778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:WinNT/Nuwar.A!sys"
        threat_id = "2147595778"
        type = "Spammer"
        platform = "WinNT: WinNT"
        family = "Nuwar"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 78 70 6c 6f 72 65 72 00 00 00 00 7a 6c 63 6c}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 6f 74 65 63 74 00 00 73 70 6f 6f 6c 64 72}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 0c 33 c0 c6 46 10 00 40 5e eb 02 33 c0}  //weight: 1, accuracy: High
        $x_1_4 = {c2 04 00 64 a1 00 00 00 00 8b 40 04 66 33 c0}  //weight: 1, accuracy: High
        $x_1_5 = {66 81 38 4d 5a 74 07 2d 00 10 00 00 eb f2 c3 55 8b ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

