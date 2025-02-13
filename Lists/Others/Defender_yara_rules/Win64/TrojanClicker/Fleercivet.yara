rule TrojanClicker_Win64_Fleercivet_A_2147688791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win64/Fleercivet.A"
        threat_id = "2147688791"
        type = "TrojanClicker"
        platform = "Win64: Windows 64-bit platform"
        family = "Fleercivet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\@system2.att" ascii //weight: 1
        $x_1_2 = {46 65 65 64 3a 20 00 00 00 00 00 00 2c 20 6d 61 78 3a 20 00 2c 20 63 6f 75 6e 74 3a 20 00 00 00 63 74 63 00 63 65 72 00 63 73 00 00 2a 2e 2a}  //weight: 1, accuracy: High
        $x_1_3 = "!IETld!Mutex_%d" wide //weight: 1
        $x_1_4 = {00 63 6c 69 63 6b 65 72 36 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win64_Fleercivet_B_2147689891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win64/Fleercivet.B"
        threat_id = "2147689891"
        type = "TrojanClicker"
        platform = "Win64: Windows 64-bit platform"
        family = "Fleercivet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f 1f 80 00 00 00 00 80 30 0a 48 8d 40 01 48 ff c9 75 f4}  //weight: 3, accuracy: High
        $x_1_2 = "_HSJ909NJJNJ90203_" ascii //weight: 1
        $x_1_3 = "cl_url1=" ascii //weight: 1
        $x_1_4 = "6576|%s.dat|" ascii //weight: 1
        $x_1_5 = {25 00 73 00 5c 00 40 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 74 00 65 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 00 73 00 5c 00 40 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 2e 00 61 00 74 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "aa19dff7[|]%08X[|]%s[|]%d[|]%s[|]127.0.0.1[|]%d[|]%d[|]%d.%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

