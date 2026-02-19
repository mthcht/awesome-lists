rule Trojan_Win64_PinkMustard_A_2147963337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PinkMustard.A!dha"
        threat_id = "2147963337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PinkMustard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CK9ILKSF.Program" ascii //weight: 2
        $x_1_2 = {61 6d 73 69 2e 64 6c 6c 00 00 00 00 00 00 00 00 55 6e 6b 6e 6f 77 6e 20 65 78 63 65 70 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 74 61 72 74 00 00 00 00 00 00 00 22 64 61 74 61 22 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = "loader.v2.dll" ascii //weight: 1
        $x_1_5 = ".workers.dev/;https://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

