rule Backdoor_Win32_Kriskynote_A_2147691115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kriskynote.A"
        threat_id = "2147691115"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kriskynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 66 0f 1f 84 00 00 00 00 00 40 30 3b 48 ff c3 40 fe c7 48 ff c9 75 f2 48 8b cd ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b6 0b ff c3 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff}  //weight: 1, accuracy: High
        $x_1_3 = "Install_uac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Kriskynote_A_2147691115_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kriskynote.A"
        threat_id = "2147691115"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kriskynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 de 83 f8 01 75 1d 33 c0 85 f6 7e 17 8a 4c 24 13 8a 14 28 32 d1 fe c1 88 14 28 40 3b c6 88 4c 24 13 7c e9 57 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = "system32\\NtUserEx" wide //weight: 1
        $x_1_3 = {8a 04 31 34 36 8a d0 80 e2 0f c0 e2 04 c0 e8 04 02 d0 88 14 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Kriskynote_B_2147691144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kriskynote.B"
        threat_id = "2147691144"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kriskynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 99 75 10 33 c0 85 db 7e 0a 30 0c 10 fe c1 40 3b c3 7c f6 5f 5e b8 01 00 00 00 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = {3b c5 76 1e 8a 04 3e 34 36 8a c8 80 e1 0f c0 e1 04 c0 e8 04 02 c8 88 0c 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Kriskynote_C_2147691155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kriskynote.C"
        threat_id = "2147691155"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kriskynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 99 85 ed 7e 0f 8a 14 18 32 d1 fe c1 88 14 18 40 3b c5 7c f1 8b 4c 24 1c}  //weight: 1, accuracy: High
        $x_1_2 = "AssecorPetaerC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

