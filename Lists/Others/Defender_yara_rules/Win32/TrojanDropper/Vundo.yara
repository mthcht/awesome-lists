rule TrojanDropper_Win32_Vundo_E_2147608160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.E"
        threat_id = "2147608160"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 35 2e 32 34 74 33 37 31 30 08 be 9f e8 bd c0 24 3f 63 6d 70 3d 74 76 c3 9c 6b 5f 75 cb 64 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Vundo_I_2147629111_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.I"
        threat_id = "2147629111"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLASSES_ROOT\\CLSID\\{50D5107A-D278-4871-8989-F4CEAAF59CFC}\\InProcServer32" ascii //weight: 1
        $x_1_2 = "msjet51.dll" ascii //weight: 1
        $x_1_3 = {66 c7 85 d8 fe ff ff d4 07 66 c7 85 da fe ff ff 08 00 66 c7 85 dc fe ff ff 03 00 66 c7 85 de fe ff ff 12 00 66 c7 85 e0 fe ff ff 0d 00 66 c7 85 e2 fe ff ff 00 00 66 c7 85 e4 fe ff ff 00 00 66 c7 85 e6 fe ff ff 00 00 8d 45 f8 50 8d 8d d8 fe ff ff 51 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Vundo_J_2147633580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.J"
        threat_id = "2147633580"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0e 83 c6 04 83 fe ?? 72 e4 33 c0 40}  //weight: 1, accuracy: Low
        $x_1_2 = {74 17 83 c7 05 83 ff ?? 72 d5 6a 2e 53 ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 0f 59 8b f7 83 c2 61 66 89 17 33 d2 f7 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Vundo_K_2147648056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.K"
        threat_id = "2147648056"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 62 56 d7 17 8d aa a7 b5 5d cb 32 c8 82 1a fa de f0 2c 36 76 dd 54 05}  //weight: 1, accuracy: High
        $x_1_2 = {89 55 e0 8b c2 c1 e8 18 c1 e2 08 0b c2 89 45 e0 2b c1 89 45 e0 33 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Vundo_M_2147649843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.M"
        threat_id = "2147649843"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 4d dc 8b f9 c1 e7 ?? c1 e9 ?? 0b cf 89 4d dc 0f b6 d2 2b ca e9 15 ff ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = {81 f9 0d 97 52 1d 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {81 f9 8d c7 87 28 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 7f 49 ab d2 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {81 f9 39 b9 12 92 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {81 f9 02 9b 49 ab 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {81 f9 b3 f6 b6 4b 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {81 f9 0b aa 18 2f 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Vundo_R_2147658032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.R"
        threat_id = "2147658032"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e7 1f 8b de 83 c4 04 89 94 01 00 10 00 00 b9 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 f1 d3 e6 00 00 81 c1 29 2e 00 00 33 ca 81 e6 ff 0f 00 00 89 94 06 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 f1 23 e0 00 00 81 e2 ff 0f 00 00 2b ce 6a 20 83 e7 1f 89 b4 02 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {89 bc 01 00 10 00 00 8b df 83 e3 1f 8b d6 bd 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {89 9c 01 00 10 00 00 8b fb 83 e7 1f 8b d6 bd 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {89 bc 01 00 10 00 00 8b d6 6a 20 8b df 83 e3 1f 59}  //weight: 1, accuracy: High
        $x_1_7 = {83 e6 1f 8b da 83 c4 04 89 bc 01 00 10 00 00 b9 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {6a 20 81 e1 ff 0f 00 00 83 e3 1f 8b d6 89 bc 01 00 10 00 00 59}  //weight: 1, accuracy: High
        $x_1_9 = {89 bc 01 00 10 00 00 8b ca c1 e9 18 c1 e2 08 0b ca 03 cf 81 f1 f4 97 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {89 bc 01 00 10 00 00 8b df 83 e3 1f b9 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {89 bc 01 00 10 00 00 8b df 83 e3 1f bd 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {89 bc 01 00 10 00 00 6a 20 8b df 59}  //weight: 1, accuracy: High
        $x_1_13 = {89 bc 01 00 10 00 00 6a 20 8b d6 8b df 83 e3 1f 59}  //weight: 1, accuracy: High
        $x_1_14 = {89 bc 01 00 10 00 00 8b ca c1 e1 17 c1 ea 09 0b ca 2b cf 8b d1 c1 e9 07 c1 e2 19 0b d1 6a 20 8b df 59}  //weight: 1, accuracy: High
        $x_1_15 = {89 bc 01 00 10 00 00 8b ca c1 e2 0d c1 e9 13 0b ca 81 c1 c1 49 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {89 bc 01 00 10 00 00 8b f7 83 e6 1f 81 f2 8f fd 00 00 b9 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {81 f6 1a a8 00 00 83 e3 1f 8b d6 89 bc 01 00 10 00 00 b9 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {81 f1 cd e9 00 00 89 94 06 00 10 00 00 03 ca 89 48 08 89 50 0c 5e}  //weight: 1, accuracy: High
        $x_1_19 = {81 f1 45 e9 00 00 89 94 06 00 10 00 00 81 e9 4f c9 00 00 89 48 08 89 50 0c 5e}  //weight: 1, accuracy: High
        $x_1_20 = {89 94 06 00 10 00 00 8b f1 c1 ee 16 c1 e1 0a 0b f1 89 50 0c 81 ee 39 ae 00 00 81 f6 d9 77 00 00}  //weight: 1, accuracy: High
        $x_1_21 = {89 94 06 00 10 00 00 81 f1 32 cf 00 00 81 c1 ee eb 00 00}  //weight: 1, accuracy: High
        $x_1_22 = {89 94 06 00 10 00 00 8b f1 c1 e6 16 c1 e9 0a 0b f1 81 ee cb f3 00 00}  //weight: 1, accuracy: High
        $x_1_23 = {81 f1 b5 c5 00 00 2b ca 81 e6 ff 0f 00 00 33 ca 89 94 06 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_24 = {89 94 06 00 10 00 00 33 ca 8b f1 c1 ee 14 c1 e1 0c 0b f1 83 c4 04 89 70 08 89 50 0c 5e}  //weight: 1, accuracy: High
        $x_1_25 = {81 f1 41 ff 00 00 81 e6 ff 0f 00 00 81 e9 48 ff 00 00 89 94 06 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_26 = {81 f1 d6 a1 00 00 81 e9 e8 b6 00 00 81 e2 ff 0f 00 00 8b de 8b f9 83 e3 1f b9 20 00 00 00 89 b4 02 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_27 = {89 b4 02 00 10 00 00 81 f1 17 c7 00 00 81 c1 a0 5b 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {81 c1 eb 88 00 00 6a 20 83 e7 1f 89 b4 02 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_29 = {89 b4 02 00 10 00 00 8b d1 c1 e9 06 c1 e2 1a 0b d1 6a 20 8b fe 59}  //weight: 1, accuracy: High
        $x_1_30 = {81 c1 bf b0 00 00 81 f1 e8 a5 00 00 2b ce 81 e2 ff 0f 00 00 89 b4 02 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_31 = {89 b4 02 00 10 00 00 8b d1 c1 e9 0a c1 e2 16 0b d1 81 f2 b2 fb 00 00}  //weight: 1, accuracy: High
        $x_1_32 = {89 b4 02 00 10 00 00 33 ce 03 ce 8b d1 c1 ea 19 c1 e1 07 0b d1 81 ea 3a 40 00 00}  //weight: 1, accuracy: High
        $x_1_33 = {81 f1 6c ed 00 00 81 e2 ff 0f 00 00 89 b4 02 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_34 = {89 b4 02 00 10 00 00 8b d1 c1 ea 11 c1 e1 0f 0b d1 59}  //weight: 1, accuracy: High
        $x_1_35 = {81 f1 d9 a2 00 00 81 e2 ff 0f 00 00 89 b4 02 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_36 = {81 f1 68 98 00 00 03 ce 81 e2 ff 0f 00 00 89 b4 02 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_37 = {89 bc 02 00 10 00 00 c1 ee 18 c1 e1 08 0b f1 81 ee f7 d9 00 00}  //weight: 1, accuracy: High
        $x_1_38 = {81 f2 5e 23 00 00 2b d7 8b f2 d3 ee 8b cb d3 e2 8b 4d 08}  //weight: 1, accuracy: High
        $x_1_39 = {81 f2 d3 41 00 00 81 ea 02 41 00 00 8b f2 d3 e6 8b cf d3 ea 5f}  //weight: 1, accuracy: High
        $x_1_40 = {89 bc 02 00 10 00 00 81 f1 5a 79 00 00 8b d1 c1 ea 14 c1 e1 0c}  //weight: 1, accuracy: High
        $x_1_41 = {81 f6 32 07 00 00 81 c6 4c 3a 00 00 81 f6 1b 79 00 00}  //weight: 1, accuracy: High
        $x_1_42 = {81 e9 4f b6 00 00 33 ce 2b ce 81 f1 d1 b0 00 00}  //weight: 1, accuracy: High
        $x_1_43 = {81 f1 e9 61 00 00 81 c1 3d 51 00 00 5e}  //weight: 1, accuracy: High
        $x_1_44 = {89 b4 01 00 10 00 00 81 f2 64 83 00 00}  //weight: 1, accuracy: High
        $x_1_45 = {89 b4 01 00 10 00 00 33 d6 8b ca c1 e9 11 c1 e2 0f 0b ca 33 ce 81 e9 f1 c5 00 00}  //weight: 1, accuracy: High
        $x_1_46 = {81 ee 33 ef 00 00 8b ce c1 e1 1a c1 ee 06 0b ce 81 e9 e7 36 00 00}  //weight: 1, accuracy: High
        $x_1_47 = {89 b4 01 00 10 00 00 8b ca c1 e2 0e c1 e9 12 0b ca 03 ce 8b d1}  //weight: 1, accuracy: High
        $x_1_48 = {89 b4 01 00 10 00 00 8b ca c1 ea 03 c1 e1 1d 0b ca 81 f1 b1 7c 00 00}  //weight: 1, accuracy: High
        $x_1_49 = {89 bc 01 00 10 00 00 8b ca c1 e2 0f c1 e9 11 0b ca 81 e9 fb c0 00 00}  //weight: 1, accuracy: High
        $x_1_50 = {81 c2 76 f9 00 00 81 f2 0d 8d 00 00 8b f2 c1 ee 0f c1 e2 11}  //weight: 1, accuracy: High
        $x_1_51 = {81 f2 31 c7 00 00 2b cf 8b da d3 eb 8b cf d3 e2}  //weight: 1, accuracy: High
        $x_1_52 = {81 ea a2 d2 00 00 33 d7 8b df 83 e3 1f}  //weight: 1, accuracy: High
        $x_1_53 = {81 c6 20 fa 00 00 83 e3 1f b9 20 00 00 00 2b cb 8b d6 d3 e2}  //weight: 1, accuracy: High
        $x_1_54 = {6a 20 81 e1 ff 0f 00 00 83 e3 1f 8b d7 89 b4 01 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_55 = {81 e2 ff 0f 00 00 89 bc 02 00 10 00 00 8b d1 c1 ea 1a}  //weight: 1, accuracy: High
        $x_1_56 = {81 e1 ff 0f 00 00 89 b4 01 00 10 00 00 8b ca c1 e9 14 c1 e2 0c}  //weight: 1, accuracy: High
        $x_1_57 = {89 b4 01 00 10 00 00 6a 20 8b fe 59 83 e7 1f}  //weight: 1, accuracy: High
        $x_1_58 = {81 f1 5a 08 00 00 81 e6 ff 0f 00 00 03 ca 89 94 06 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_59 = {89 bc 02 00 10 00 00 8b d1 c1 ea 1d c1 e1 03 0b d1 81 c2 13 b7 00 00}  //weight: 1, accuracy: High
        $x_1_60 = {89 94 01 00 10 00 00 8b ce c1 e6 02 c1 e9 1e 0b ce 81 e9 46 4e 00 00}  //weight: 1, accuracy: High
        $x_1_61 = {89 b4 01 00 10 00 00 8b fe 83 e7 1f b9 20 00 00 00 2b cf 8b da d3 eb 8b cf d3 e2 83 c4 04}  //weight: 1, accuracy: High
        $x_1_62 = {89 b4 01 00 10 00 00 59 2b cf 89 70 0c d3 eb 8b cf 5f d3 e2 0b da 03 de 5e 81 f3 8b 76 00 00}  //weight: 1, accuracy: High
        $x_1_63 = {81 ea d3 67 00 00 8b f2 d3 e6 8b cb d3 ea 5f 0b f2 89 70 08}  //weight: 1, accuracy: High
        $x_1_64 = {89 b4 01 00 10 00 00 8b ca c1 ea 08 c1 e1 18 0b ca 81 f1 3e 42 00 00}  //weight: 1, accuracy: High
        $x_1_65 = {81 c6 91 53 00 00 8b fe d3 e7 8b cb d3 ee 8b c8 8b 44 24 10}  //weight: 1, accuracy: High
        $x_1_66 = {81 c6 af 81 00 00 8b d6 c1 e6 0e c1 ea 12 0b d6 03 d7 8b f2}  //weight: 1, accuracy: High
        $x_1_67 = {81 f1 fc 95 00 00 8b d1 c1 e2 12 c1 e9 0e 0b d1 03 d6 89 70 0c}  //weight: 1, accuracy: High
        $x_1_68 = {81 e9 9c f4 00 00 8b d1 c1 e9 09 c1 e2 17 0b d1 81 ea 3c ac 00 00}  //weight: 1, accuracy: High
        $x_1_69 = {89 bc 02 00 10 00 00 8b d1 c1 ea 1c c1 e1 04 0b d1 59 81 f2 29 1c 00 00}  //weight: 1, accuracy: High
        $x_1_70 = {89 b4 01 00 10 00 00 8b ca c1 e2 09 c1 e9 17 0b ca 2b ce 33 ce 8b d1 c1 e2 16 c1 e9 0a 0b d1 03 d6 83 c4 04 89 70 0c 89 50 08}  //weight: 1, accuracy: High
        $x_1_71 = {89 b4 01 00 10 00 00 8b fe 33 d6 83 e7 1f b9 20 00 00 00 2b cf 8b da d3 eb 8b cf 83 c4 04 d3 e2 5f 89 70 0c 5e 0b da 89 58 08}  //weight: 1, accuracy: High
        $x_1_72 = {89 b4 01 00 10 00 00 b9 20 00 00 00 2b cb 89 70 0c d3 e2 8b cb d3 ef 0b d7 5f 03 d6 8b ca c1 e1 1d c1 ea 03 0b ca 03 ce 33 ce 8b d1 c1 ea 17 c1 e1 09 0b d1 2b d6 5e 89 50 08}  //weight: 1, accuracy: High
        $x_1_73 = {89 bc 02 00 10 00 00 81 f1 14 01 00 00 2b cf 8b d1 c1 ea 1f 03 c9 0b d1 03 d7 8b df 83 e3 1f 8b f2 b9 20 00 00 00 2b cb d3 ee 8b cb d3 e2 83 c4 04 89 78 0c}  //weight: 1, accuracy: High
        $x_1_74 = {89 bc 02 00 10 00 00 8b d1 c1 e2 13 c1 e9 0d 0b d1 03 d7 8b df 83 e3 1f 8b f2 bd 20 00 00 00 2b eb 8b cd d3 ee 8b cb d3 e2 8b cd 83 c4 04 89 78 0c}  //weight: 1, accuracy: High
        $x_1_75 = {89 94 06 00 10 00 00 8b f1 c1 e6 1e c1 e9 02 0b f1 33 f2 81 ee 39 ab 00 00 81 f6 53 98 00 00}  //weight: 1, accuracy: High
        $x_1_76 = {81 c6 7e 47 00 00 8b fe d3 e7 8b 4d 10 d3 ee 8b 4d 0c 0b fe 81 ef a1 66 00 00}  //weight: 1, accuracy: High
        $x_1_77 = {89 bc 02 00 10 00 00 c1 ee 13 0b f1 8b df 81 c6 24 81 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Vundo_AA_2147681306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.AA"
        threat_id = "2147681306"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Elevation:Administrator!new:{" wide //weight: 1
        $x_1_2 = "\"LoadAppInit_DLLs\"=dword:00000001" ascii //weight: 1
        $x_1_3 = {5c 49 74 65 72 72 61 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 41 64 64 49 74 65 72 72 61 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 30 31 30 35 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 54 30 33 65 6d 70 30 33 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 54 30 34 65 6d 70 30 34 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_2_8 = {8b 55 f8 8b 45 f0 8a 88 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? 8b 55 f8 0f be 82 ?? ?? ?? ?? 83 f8 5c 75 1b 8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 8b 45 f0 8a 88 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? 8b 55 f8 83 c2 01 89 55 f8 eb a0}  //weight: 2, accuracy: Low
        $x_1_9 = {0f c8 89 45 f8 c7 45 ec b9 79 37 9e 8b 4d ec 0f af 4d f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Vundo_AB_2147684724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vundo.AB"
        threat_id = "2147684724"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f3 0f b7 44 15 ?? 03 c1 33 d2 f7 b5 ?? ff ff ff 8a 04 3e 8b ca 8a 14 39 88 14 3e 46 88 04 39 3b b5 ?? ff ff ff 72 cd ff 45 ?? 83 7d ?? 64 72 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ff 75 61 6c 41 75 ?? 81 fb 6c 6c 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = {81 ff 75 61 6c 51 75 ?? 81 fb 75 65 72 79}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ff 75 61 6c 46 75 ?? 81 fb 72 65 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

