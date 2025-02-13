rule Trojan_Win32_Sadacal_A_2147645423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sadacal.A"
        threat_id = "2147645423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sadacal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 56 6a 13 ff 75 ?? c7 45 ?? 0a 00 00 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {c6 45 d4 5c 47 e8 ?? ?? ?? ?? 6a 1a 99 59 f7 f9 80 c2 61 88 54 3d d4 47 83 ff 0b}  //weight: 5, accuracy: Low
        $x_1_3 = "task/acc" ascii //weight: 1
        $x_1_4 = "task/files" ascii //weight: 1
        $x_1_5 = "task/code" ascii //weight: 1
        $x_3_6 = {70 61 79 6d 65 6e 74 00 75 70 6c 6f 61 64 00 00 70 72 6f 63 65 73 73 00 73 74 61 74}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

