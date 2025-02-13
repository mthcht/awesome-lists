rule Backdoor_Win32_Misdat_A_2147696120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Misdat.A!dha"
        threat_id = "2147696120"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Misdat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6c 69 73 74 65 72 72 6f 72 7c}  //weight: 1, accuracy: High
        $x_1_2 = {00 66 69 6c 65 6c 69 73 74 7c}  //weight: 1, accuracy: High
        $x_1_3 = {00 73 68 65 6c 6c 64 61 74 61 7c}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 68 65 6c 6c 73 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_5 = "&type=post&stype=" ascii //weight: 1
        $x_1_6 = "stype=info&data=" ascii //weight: 1
        $x_1_7 = "stype=srv&data=" ascii //weight: 1
        $x_1_8 = "stype=con&data=" ascii //weight: 1
        $x_1_9 = "stype=user&data=" ascii //weight: 1
        $x_1_10 = {33 d2 8a 16 c1 ea 04 83 e2 0f 8a 92 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff ?? ?? 8d ?? ?? 8a 16 80 e2 0f 81 e2 ff 00 00 00 8a 92 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ?? 8b c7 ba 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {c1 e9 08 32 d1 88 54 18 ff 8b 45 f4 0f b6 44 18 ff 03 45 f8 69 c0 ?? ?? 00 00 05 ?? 00 00 89 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

