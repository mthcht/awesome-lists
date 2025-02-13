rule Trojan_Win64_R2d2_A_2147651145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/R2d2.A"
        threat_id = "2147651145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "R2d2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 41 b9 8e 20 03 00 41 b8 ef 01 00 00 8d 4a 01 48 c7 44 24 20 a8 c5 00 00 ff 15 ?? ?? ?? ?? cc}  //weight: 5, accuracy: Low
        $x_1_2 = "\\Driver\\kbdclass" wide //weight: 1
        $x_1_3 = "ZwSetInformationFile" ascii //weight: 1
        $x_1_4 = "PoStartNextPowerIrp" ascii //weight: 1
        $x_5_5 = "PendingFileRenameOperations" wide //weight: 5
        $x_5_6 = "\\Device\\KeyboardClassC" wide //weight: 5
        $x_1_7 = {3d 34 00 00 c0}  //weight: 1, accuracy: High
        $x_1_8 = {b8 9a 00 00 c0}  //weight: 1, accuracy: High
        $x_1_9 = {bb 10 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

