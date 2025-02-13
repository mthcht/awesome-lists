rule Trojan_Win32_Gruwt_B_2147639778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gruwt.B"
        threat_id = "2147639778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gruwt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 81 ff fe 00 00 00 72 e0 8d 54 24 ?? 6a 03 52 8d 4c 24 ?? e8 ?? ?? ?? ?? 33 ff 8d 4c 24 ?? e8 ?? ?? ?? ?? 8a 97 ?? ?? ?? ?? 32 d0 88 97}  //weight: 2, accuracy: Low
        $x_1_2 = "Action.SpamConfirm" wide //weight: 1
        $x_1_3 = "Oops!...I did it again" ascii //weight: 1
        $x_1_4 = {67 65 74 66 69 6c 65 3a 20 25 75 00 25 25 74 65 6d 70 25 25 5c 7e 74 6d 70 25 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = {43 72 65 61 74 65 66 69 6c 65 3a 20 25 75 [0-5] 44 4c 20 6f 6b [0-5] 72 75 6e 3a 20 25 75}  //weight: 1, accuracy: Low
        $x_1_6 = "Passwd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

