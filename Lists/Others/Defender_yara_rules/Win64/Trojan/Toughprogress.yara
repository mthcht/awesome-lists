rule Trojan_Win64_Toughprogress_A_2147943064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Toughprogress.A"
        threat_id = "2147943064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Toughprogress"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1008"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1000, accuracy: High
        $x_100_2 = "ff57964096cadc1a8733cf566b41c9528c89d30edec86326c723932c1e79ebf0@group.calendar.google.com" wide //weight: 100
        $x_100_3 = "104075625139-l53k83pb6jbbc2qbreo4i5a0vepen41j.apps.googleusercontent.com" ascii //weight: 100
        $x_5_4 = {65 00 76 00 65 00 6e 00 74 00 73 00 3f 00 74 00 69 00 6d 00 65 00 4d 00 69 00 6e 00 3d 00 32 00 30 00 ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? 54 00 30 00 30 00 25 00 33 00 41 00 30 00 30 00 25 00 33 00 41 00 30 00 30 00 5a 00 26 00 74 00 69 00 6d 00 65 00 4d 00 61 00 78 00 3d 00 32 00 30 00 ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? 54 00 32 00 33 00 25 00 33 00 41 00 35 00 39 00 25 00 33 00 41 00 35 00 39 00 5a 00 26 00 73 00 69 00 6e 00 67 00 6c 00 65 00 45 00 76 00 65 00 6e 00 74 00 73 00 3d 00 74 00 72 00 75 00 65 00 26 00 6f 00 72 00 64 00 65 00 72 00 42 00 79 00 3d 00 73 00 74 00 61 00 72 00 74 00 54 00 69 00 6d 00 65 00}  //weight: 5, accuracy: Low
        $x_2_5 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 70 00 69 00 2e 00 69 00 70 00 69 00 66 00 79 00 2e 00 6f 00 72 00 67 00 90 00 01 00 02 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 90 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = "{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" wide //weight: 2
        $x_2_7 = {2f 00 65 00 76 00 65 00 6e 00 74 00 73 00 2f 00 90 00 01 00 02 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 61 00 70 00 69 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2f 00 76 00 33 00 2f 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 73 00 2f 00 90 00 00 00}  //weight: 2, accuracy: High
        $x_2_8 = "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" ascii //weight: 2
        $x_2_9 = "1//0gl_dqTwZXSGcCgYIARAAGBASNwF-L9IrpqwPk_sIrJ8wYL5fwSoeM4ABGbsnMRGg2DEDKtERK7IbBYYlRxekosnxvq_BIyBIq14" ascii //weight: 2
        $x_2_10 = "RetpolineV1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 4 of ($x_2_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_100_*))) or
            (all of ($x*))
        )
}

