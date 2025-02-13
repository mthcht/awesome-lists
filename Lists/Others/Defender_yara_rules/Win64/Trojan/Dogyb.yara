rule Trojan_Win64_Dogyb_B_2147734934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dogyb.B!dha"
        threat_id = "2147734934"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dogyb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 41 64 64 2e 64 6c 6c 00 41 64 64 42 79 47 6f 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 45 00 ff 10}  //weight: 1, accuracy: High
        $x_1_3 = {ba 10 66 00 00 [0-8] 41 b9 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dogyb_D2_2147734935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dogyb.D2!dha"
        threat_id = "2147734935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dogyb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gSharedInfo" ascii //weight: 1
        $x_1_2 = "NtUserDefSetText" ascii //weight: 1
        $x_1_3 = "#32772" wide //weight: 1
        $x_1_4 = {65 78 70 6c 6f 69 74 20 73 75 63 63 65 73 73 21 0a}  //weight: 1, accuracy: High
        $x_1_5 = {65 78 70 6c 6f 69 74 20 66 61 69 6c 65 64 21 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

