rule Backdoor_Win64_Hikiti_N_2147693120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Hikiti.N!dha"
        threat_id = "2147693120"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c2 32 c2 88 01 48 8d 41 01 33 c9 0f 1f 80 00 00 00 00 30 14 01 74 0c 48 ff c1 48 81 f9 03 01 00 00 7c ef}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 26 ed c6 44 24 27 ed c6 44 24 28 ee c6 44 24 29 e2 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Hikiti_O_2147693125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Hikiti.O!dha"
        threat_id = "2147693125"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 32 c0 88 01 48 8d 41 01 4c 8b c8 48 8b d0 49 f7 d9 44 30 02 74 10 48 ff c2 49 8d 0c 11 48 81 f9 03 01 00 00 7c eb f3 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b d3 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 74 02 ff d0 48 8b 4d ?? 48 33 cc e8 ?? ?? ?? ?? 48 8b 5c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

