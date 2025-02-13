rule Ransom_Win32_Criakl_A_2147688295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Criakl.A"
        threat_id = "2147688295"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Criakl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "{CRYPTENDBLACKDC}" ascii //weight: 2
        $x_1_2 = "{CRYPTFULLEND" ascii //weight: 1
        $x_1_3 = "{CRYPTSTARTDATA}" ascii //weight: 1
        $x_1_4 = "notthisoperationisay" ascii //weight: 1
        $x_1_5 = ":*.mdf:*.xls:*.DT:" ascii //weight: 1
        $x_1_6 = {7b 4d 59 49 44 7d [0-16] 7b 4d 59 4d 41 49 4c 7d}  //weight: 1, accuracy: Low
        $x_1_7 = "*.pptx|||{}|||000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Criakl_D_2147697386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Criakl.D"
        threat_id = "2147697386"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Criakl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 7b 45 4e 43 52 59 50 54 45 4e 44 45 44 7d 00}  //weight: 1, accuracy: High
        $x_1_2 = {7b 42 4c 4f 43 4b 53 53 54 41 52 54 7d 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 72 61 6e 64 6f 6d 6e 61 6d 65 2d 00}  //weight: 1, accuracy: High
        $x_1_4 = {7b 42 4c 4f 43 4b 53 45 4e 44 7d 00}  //weight: 1, accuracy: High
        $x_2_5 = {66 64 62 3a 66 62 66 3a 6d 61 78 3a 6d 33 64 3a (64 62 66 3a 6c|6c 64 66 3a 6b 65 79 73 74 6f) 3a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Criakl_F_2147722505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Criakl.F!bit"
        threat_id = "2147722505"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Criakl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8b 84 9d 00 fc ff ff 03 f0 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a c8 8b 84 b5 00 fc ff ff 89 84 9d 00 fc ff ff 0f b6 c1 89 84 b5 00 fc ff ff 8b 8c 9d 00 fc ff ff 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 84 8d 00 fc ff ff 8b 4d 10 30 04 0a 42 3b d7 72 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

