rule Trojan_Win32_Boaxxe_B_2147598164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.B"
        threat_id = "2147598164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 07 e8 ?? ?? ?? ff 8b e8 85 ed 7e 2d be 01 00 00 00 83 c3 11 6b c3 71 25 ff 00 00 00 8b d8 88 1c 24 8b c7 e8 ?? ?? ?? ff 8b 17 8a 54 32 ff 32 14 24 88 54 30 ff 46 4d 75 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 0b 00 00 00 e8 ?? ?? ?? ?? 8d 55 d8 8b 45 ?? e8 ?? ?? ?? ?? ff 75 d8 68 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? ba 03 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Boaxxe_C_2147598866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.C"
        threat_id = "2147598866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 47 89 45 e4 c7 45 ec 01 00 00 00 8b 45 f0 83 c0 11 6b c0 71 25 ff 00 00 00 89 45 f0 8a 45 f0 88 45 eb 8b 45 f4 e8 ?? ?? ?? ff 8b 55 ec 8b 4d f4 8b 09 8b 5d ec 8a 4c 19 ff 32 4d eb 88 4c 10 ff ff 45 ec ff 4d e4 75 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 0b 00 00 00 e8 ?? ?? ?? ?? 8d 55 ?? 8b 45 f4 e8 ?? ?? ?? ?? ff 75 ?? 68 ?? ?? ?? ?? ff 75 dc 8d 45 f4 ba 03 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Boaxxe_E_2147610500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.E"
        threat_id = "2147610500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 18 30 1a (42|4a) 75 f7 8d 55 ?? 8d 45 ?? b9}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 e4 8a 80 ?? ?? ?? ?? 8b 55 e4 30 44 15 ?? ff 45 e4 83 7d e4 08 75 e7}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 08 53 6a 00 6a 00 68 44 00 22 00}  //weight: 2, accuracy: High
        $x_2_4 = {b9 00 4c 01 00 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 84 c0 74 15}  //weight: 2, accuracy: Low
        $x_2_5 = {05 a0 0d 00 00 50 53 e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_2_6 = {72 06 04 fa 2c 1a 73 19 8d 45 ?? 8b 17 8a 54 1a ff}  //weight: 2, accuracy: Low
        $x_1_7 = {08 54 55 70 64 61 74 65 72 90 ff ff ff ff 09 00 00 00 54 69 6d 65 53 74 61 6d 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {06 54 50 72 6f 74 52 90 ff ff ff ff 07 00 00 00 56 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_9 = {6d 75 31 00 ff ff ff ff 03 00 00 00 6d 65 31 00}  //weight: 1, accuracy: High
        $x_1_10 = "sin32sdl.dll" ascii //weight: 1
        $x_1_11 = "smlrx32.dll" ascii //weight: 1
        $x_1_12 = {0f b7 40 14 03 ?? 8b 45 ?? 0f b7 ?? 06 ?? 85 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_13 = {88 50 03 8d 45 f0 e8 ?? ?? ?? ?? 8a 55 f9 88 50 06 8d 45 f0 e8 ?? ?? ?? ?? 8a 55 fa 88 50 09}  //weight: 1, accuracy: Low
        $x_1_14 = {ff b0 fc 11 00 00 8b 45 fc 05 84 00 00 00 ba 1d 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {8b 43 6c 8b 90 84 04 00 00 52 05 a0 0d 00 00 50}  //weight: 1, accuracy: High
        $x_1_16 = {70 72 6f 78 31 00 00 00 55 8b ec 33 c0 55 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Boaxxe_E_2147610500_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.E"
        threat_id = "2147610500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 61 62 69 6f 72 6b 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 00 61 6d 67 73 77 6d 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 00 61 6f 79 71 75 6c 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 00 61 72 63 79 6d 62 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 00 61 74 69 79 6a 69 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 00 41 58 53 4c 45 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 00 00 62 64 75 66 6e 63 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 00 00 62 6d 67 69 74 73 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 00 00 62 79 66 6d 78 64 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 00 00 63 68 75 74 6f 73 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 00 00 63 6b 6e 66 65 62 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 00 00 63 78 79 65 77 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 00 00 64 61 68 76 61 72 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 00 00 64 64 6c 77 75 62 78 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 00 00 64 67 74 67 75 78 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 00 00 64 68 67 71 79 68 7a 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_17 = {00 00 00 64 69 75 65 71 6f 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 00 00 64 69 79 77 70 6f 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 00 00 64 6e 66 61 61 6a 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_20 = {00 00 00 64 72 74 66 74 67 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_21 = {00 00 00 65 61 62 6d 78 6a 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_22 = {00 00 00 65 78 68 72 71 76 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_23 = {00 00 00 65 79 78 78 63 70 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_24 = {00 00 00 66 70 62 72 65 68 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_25 = {00 00 00 66 71 74 6c 76 62 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_26 = {00 00 00 66 73 77 63 75 78 71 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_27 = {00 00 00 66 74 75 6d 6b 6c 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_28 = {00 00 00 67 63 6c 78 79 69 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_29 = {00 00 00 67 6b 63 61 75 61 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_30 = {00 00 00 67 6d 69 67 77 6d 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_31 = {00 00 00 68 65 61 75 73 7a 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_32 = {00 00 00 68 67 6f 61 6e 67 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_33 = {00 00 00 68 6a 77 63 71 6f 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_34 = {00 00 00 68 75 77 72 75 65 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_35 = {00 00 00 69 65 76 76 79 71 61 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_36 = {00 00 00 69 67 6d 61 79 78 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_37 = {00 00 00 69 6b 6a 73 71 75 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_38 = {00 00 00 6a 66 70 78 6f 63 70 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_39 = {00 00 00 6a 67 76 6a 65 6c 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_40 = {00 00 00 6a 6b 71 6e 65 75 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_41 = {00 00 00 6b 63 76 64 67 71 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_42 = {00 00 00 6b 66 78 70 61 6a 67 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_43 = {00 00 00 6b 77 65 63 61 65 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_44 = {00 00 00 6c 62 68 71 79 72 6c 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_45 = {00 00 00 6c 63 77 76 6a 68 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_46 = {00 00 00 6c 6b 6f 77 6f 66 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_47 = {00 00 00 6c 6f 6f 69 71 7a 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_48 = {00 00 00 6c 75 6b 6f 77 6f 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_49 = {00 00 00 6d 62 78 75 68 66 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_50 = {00 00 00 6d 63 6c 62 63 74 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_51 = {00 00 00 6d 66 74 6d 6d 78 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_52 = {00 00 00 6d 6d 6a 76 77 65 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_53 = {00 00 00 6d 71 76 6b 6f 64 78 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_54 = {00 00 00 6d 75 6a 78 74 78 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_55 = {00 00 00 6e 66 76 6d 74 6d 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_56 = {00 00 00 6e 6d 69 74 66 63 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_57 = {00 00 00 6f 66 70 69 62 62 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_58 = {00 00 00 6f 70 6e 6d 6b 67 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_59 = {00 00 00 6f 76 69 73 6e 6c 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_60 = {00 00 00 70 64 72 64 66 79 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_61 = {00 00 00 70 6c 74 65 65 77 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_62 = {00 00 00 70 6d 6c 72 75 71 71 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_63 = {00 00 00 70 71 72 66 65 70 71 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_64 = {00 00 00 71 61 65 6f 6b 6b 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_65 = {00 00 00 71 61 6a 66 62 61 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_66 = {00 00 00 71 67 6f 6f 6a 6d 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_67 = {00 00 00 71 6b 69 6c 6f 67 72 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_68 = {00 00 00 71 6f 62 6e 68 73 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_69 = {00 00 00 71 70 7a 6e 70 79 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_70 = {00 00 00 71 74 6e 77 63 72 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_71 = {00 00 00 71 75 68 75 68 68 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_72 = {00 00 00 71 76 70 6d 77 69 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_73 = {00 00 00 71 78 72 6a 79 78 64 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_74 = {00 00 00 71 79 6c 6e 74 72 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_75 = {00 00 00 72 69 6f 6d 62 66 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_76 = {00 00 00 72 6d 65 73 6d 75 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_77 = {00 00 00 72 76 64 6b 6f 74 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_78 = {00 00 00 72 78 6f 71 75 6f 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_79 = {00 00 00 73 62 6c 69 68 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_80 = {00 00 00 73 66 7a 63 6c 69 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_81 = {00 00 00 73 6d 6c 72 78 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_82 = {00 00 00 73 74 64 65 65 6e 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_83 = {00 00 00 73 78 65 6b 65 6e 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_84 = {00 00 00 73 7a 66 6d 73 73 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_85 = {00 00 00 74 64 64 6d 73 6e 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_86 = {00 00 00 74 68 6c 6c 78 69 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_87 = {00 00 00 74 66 78 78 63 6c 6e 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_88 = {00 00 00 74 71 73 6d 75 76 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_89 = {00 00 00 75 68 69 63 62 72 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_90 = {00 00 00 75 6b 69 6b 62 6c 71 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_91 = {00 00 00 75 6d 78 61 76 68 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_92 = {00 00 00 75 77 6b 69 6e 63 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_93 = {00 00 00 76 67 64 61 6e 68 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_94 = {00 00 00 76 67 66 6c 77 74 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_95 = {00 00 00 76 68 69 78 76 6c 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_96 = {00 00 00 76 6a 62 70 6f 77 6b 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_97 = {00 00 00 76 70 64 66 72 6b 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_98 = {00 00 00 76 76 62 64 73 6e 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_99 = {00 00 00 76 7a 67 78 75 65 79 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_100 = {00 00 00 77 6b 6e 64 67 77 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_101 = {00 00 00 77 6e 66 61 73 77 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_102 = {00 00 00 77 6f 62 67 6a 7a 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_103 = {00 00 00 77 77 71 62 69 66 6e 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_104 = {00 00 00 77 79 71 72 76 6f 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_105 = {00 00 00 78 62 79 70 7a 71 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_106 = {00 00 00 78 6a 67 62 63 65 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_107 = {00 00 00 78 6a 6b 6c 68 72 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_108 = {00 00 00 78 6d 63 70 76 6e 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_109 = {00 00 00 78 75 69 6d 68 69 76 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_110 = {00 00 00 78 7a 72 78 65 63 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_111 = {00 00 00 79 63 64 68 73 7a 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_112 = {00 00 00 79 64 7a 6b 77 7a 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_113 = {00 00 00 79 70 6a 79 74 6c 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_114 = {00 00 00 79 72 68 70 63 68 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_115 = {00 00 00 79 76 77 73 79 61 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_116 = {00 00 00 7a 6d 76 6f 72 74 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_117 = {00 00 00 7a 70 67 68 67 6b 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_118 = {00 00 00 6d 6c 6e 74 7a 6f 7a 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_119 = {00 00 00 72 72 62 6e 72 65 72 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_120 = {00 00 00 78 72 78 6e 75 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_121 = {00 00 00 71 64 64 71 69 78 74 77 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_122 = {00 00 00 6e 64 6a 64 6f 71 70 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_123 = {00 00 00 41 56 46 6f 75 6e 64 61 74 69 6f 6e 43 46 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_124 = {00 00 00 53 44 50 50 4c 49 4e 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_125 = {00 00 00 64 65 6c 65 67 61 74 65 5f 65 78 65 63 75 74 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_126 = {00 00 00 45 50 37 55 49 50 30 30 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_127 = {00 00 00 41 53 4d 69 6d 70 6f 72 74 32 31 36 41 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_128 = {00 00 00 68 70 6f 63 35 33 30 33 2e 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Boaxxe_F_2147610501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.F"
        threat_id = "2147610501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 09 89 d0 31 07 83 c7 04 e2 f9}  //weight: 1, accuracy: High
        $x_1_2 = {61 6a 00 68 6f 75 6e 74}  //weight: 1, accuracy: High
        $x_1_3 = {3d 2e 54 4d 50 0f 85 ?? ?? ?? ?? 68 78 41 00 00}  //weight: 1, accuracy: Low
        $x_2_4 = {8b 86 cc 00 00 00 89 c2 e8 00 00 00 00 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Boaxxe_J_2147616895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.J"
        threat_id = "2147616895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 07 00 00 76 05 83 c8 ff eb 38}  //weight: 1, accuracy: High
        $x_1_2 = {00 95 01 00 00 73 07 b8 06 00 00 00 eb 18 81 ?? ?? ?? ?? 00 2f 03 00 00 73 07 b8 02 00 00 00 eb 05}  //weight: 1, accuracy: Low
        $x_1_3 = {35 92 56 00 00 [0-16] 00 79 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d ec 83 c1 01 89 4d ec 83 7d ec 65 7d 16 6a 03 e8 ?? ?? ?? ?? 83 c4 04 6a 0c e8 ?? ?? ?? ?? 83 c4 04 eb db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Boaxxe_M_2147648960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.M"
        threat_id = "2147648960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 bf 2c 1a 72 06 04 fa 2c 1a 73 19}  //weight: 4, accuracy: High
        $x_4_2 = {33 db eb 47 6a 28 6a 40 e8 ?? ?? ?? ?? 89 04 24 6a 00 8d 44 24 08 50 6a 04 8b 44 24 0c 50 6a 00 6a 00 68 18 00 22 00}  //weight: 4, accuracy: Low
        $x_1_3 = {64 72 64 6c 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 72 6c 73 33 32 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 6d 33 32 77 69 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Boaxxe_R_2147717907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boaxxe.R!bit"
        threat_id = "2147717907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 69 00 00 00 8b 0d ?? ?? ?? ?? 66 89 01 ba 6e 00 00 00 a1 ?? ?? ?? ?? 66 89 50 02 b9 66 00 00 00 8b 15 ?? ?? ?? ?? 66 89 4a 0a b8 61 00 00 00 8b 0d ?? ?? ?? ?? 66 89 41 0c ba 63 00 00 00 a1 ?? ?? ?? ?? 66 89 50 0e b9 7b 00 00 00 8b 15 ?? ?? ?? ?? 66 89 4a 14 b8 7d 00 00 00 8b 0d ?? ?? ?? ?? 66 89 41 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 a3 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? c6 01 56 8b 95 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 b0 60 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {72 02 eb 2a 8b 45 ?? 89 85 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ?? ?? 8b 55 ?? 03 95 ?? ?? ?? ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

