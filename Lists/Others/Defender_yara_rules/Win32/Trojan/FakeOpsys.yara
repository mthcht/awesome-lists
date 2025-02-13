rule Trojan_Win32_FakeOpsys_2147624527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeOpsys"
        threat_id = "2147624527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeOpsys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 40 1c 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 8b 80 ?? ?? ?? ?? ba 80 ee 36 00}  //weight: 2, accuracy: Low
        $x_3_2 = {64 65 66 00 ff ff ff ff 03 00 00 00 69 64 69 00}  //weight: 3, accuracy: High
        $x_2_3 = {0d 62 75 74 74 5f 73 74 6f 70 73 63 61 6e}  //weight: 2, accuracy: High
        $x_1_4 = {07 51 53 54 69 6d 65 72}  //weight: 1, accuracy: High
        $x_1_5 = {0d 6f 6e 6c 73 65 74 74 69 6e 67 73 5f 75}  //weight: 1, accuracy: High
        $x_1_6 = "aplication and consult" ascii //weight: 1
        $x_1_7 = "Operation system kernel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

