rule Trojan_Win64_DragonFruit_A_2147980355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DragonFruit.A!dha"
        threat_id = "2147980355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DragonFruit"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s%ld MB" ascii //weight: 1
        $x_1_2 = "%s%ld KB" ascii //weight: 1
        $x_2_3 = {00 00 31 6c 6c 6c 6c 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 20 20 25 64 20 72 65 73 75 6c 74 28 73 29 00}  //weight: 2, accuracy: High
        $x_2_5 = {6a 64 ff d6 6a 01 e8 ?? ?? ?? ?? 83 c4 04 3b ?? 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

