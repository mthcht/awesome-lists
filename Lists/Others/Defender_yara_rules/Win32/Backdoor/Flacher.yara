rule Backdoor_Win32_Flacher_A_2147691672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Flacher.A!dha"
        threat_id = "2147691672"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Flacher"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 09 80 34 38 7e 40 3b c3 72 f7 6a 00 8d 45 f0 50 53 57 56 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c7 85 18 fd ff ff 64 00 00 00 ff b5 20 fd ff ff c7 85 10 fd ff ff 05 01 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {2b c7 d1 f8 50 51 6a 2b ff b5 60 fe ff ff ff d6 6a 01 53 6a 03 53 53 ff}  //weight: 1, accuracy: High
        $x_1_4 = {69 c0 44 33 22 11 41 0f af c8 6a 04 8d 44 24 40 50 57 56 89 4c 24}  //weight: 1, accuracy: High
        $x_1_5 = {8a 08 40 84 c9 75 f9 2b c2 53 8b d8 80 7c 3b ff ?? 75 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Flacher_B_2147706804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Flacher.B!dha"
        threat_id = "2147706804"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Flacher"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 08 40 84 c9 75 f9 2b c2 53 8b d8 80 7c 3b ff ?? 75 3e}  //weight: 3, accuracy: Low
        $x_3_2 = {74 09 80 34 30 7e 40 3b c7 72 f7 6a 00 8d 45 f0 50 57 56 53 ff 15 20 f2 43 00 53 ff 15 10 f2 43 00 33 c0 85 ff 74 09 80 34 30 7e 40 3b c7}  //weight: 3, accuracy: High
        $x_1_3 = "exec_rescue" ascii //weight: 1
        $x_1_4 = {74 00 73 00 74 00 61 00 6d 00 70 00 00 00 00 00 74 00 61 00 73 00 6b 00 6b 00 00 00 74 00 61 00 73 00 6b 00 6c 00 00 00 73 00 68 00 72 00 65 00 64 00 00 00 76 00 6f 00 6c 00 00 00 76 00 65 00 72 00 69 00 66 00 79 00 00 00 00 00 74 00 79 00 70 00 65 00 00 00 00 00 74 00 69 00 6d 00 65 00 72 00 00 00 73 00 74 00 61 00 72 00 74 00 00 00 73 00 68 00 69 00 66 00 74 00}  //weight: 1, accuracy: High
        $x_1_5 = "runfile: couldn't find shellexecuteexa/w in shell32.dll!" ascii //weight: 1
        $x_1_6 = "debug: cannot allocate memory for ptrfilearray!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

