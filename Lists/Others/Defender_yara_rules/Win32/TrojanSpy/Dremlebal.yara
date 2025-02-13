rule TrojanSpy_Win32_Dremlebal_A_2147697617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dremlebal.A"
        threat_id = "2147697617"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dremlebal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = "2011\\RewriteDM-ball\\playUnIEvoke\\Release\\playUnIEvoke.pdb" ascii //weight: 8
        $x_2_2 = {50 68 00 28 00 00 8d 8d ec cf ff ff 51 57 c7 85 ?? ?? ff ff 00 00 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {2e 64 6c 6c 00 54 75 72 6e 61 4c 33 00 69 6e 64 65 78 2e 68 74 6d 3f}  //weight: 1, accuracy: High
        $x_1_4 = {6d 6d 73 00 74 61 74 00 74 61 6f 00 62 61 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 65 64 69 61 76 00 00 65 79 65 30 38 37 31 00 73 74 75 64 65 6e 74 2e 71 71}  //weight: 1, accuracy: High
        $x_1_6 = {69 63 6b 00 73 63 6f 72 65 63 61 72 00 00 00 00 64 72 65 73 65 61 72 63 68 00 00 00 62 61 6c 61}  //weight: 1, accuracy: High
        $x_1_7 = {72 70 63 2e 61 70 70 00 2e 73 68 6f 70 65 78}  //weight: 1, accuracy: High
        $x_1_8 = {31 74 6f 31 63 72 6d 31 00 00 00 00 69 70 69 6e 79 6f 75 00 73 65 64 72 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

