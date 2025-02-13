rule Trojan_Win32_Autophyte_A_2147724706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.A!dha"
        threat_id = "2147724706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 2f 00 35 00 05 00 0a [0-8] c0 13 c0 14 [0-8] c0 09 c0 0a [0-8] 00 32 00 38 [0-8] 00 13 00 04}  //weight: 1, accuracy: Low
        $x_1_2 = {00 2f 00 35 c7 [0-8] 00 05 00 0a [0-8] c0 13 c0 14 [0-8] c0 09 c0 0a [0-8] 00 32 00 38 [0-8] 00 13 00 04}  //weight: 1, accuracy: Low
        $x_1_3 = {00 04 00 05 00 0a 00 09 [0-8] 00 64 00 62 [0-8] 00 03 00 06 [0-8] 00 13 00 12 [0-8] 00 63}  //weight: 1, accuracy: Low
        $x_1_4 = {00 04 00 05 c7 [0-8] 00 0a 00 09 [0-8] 00 64 00 62 [0-8] 00 03 00 06 [0-8] 00 13 00 12 [0-8] 00 63}  //weight: 1, accuracy: Low
        $x_1_5 = {00 ff c0 0a c0 14 00 88 [0-8] 00 87 00 39 [0-8] 00 38 c0 0f [0-8] c0 05 00 84 [0-8] 00 35 c0 07 [0-8] c0 09 c0}  //weight: 1, accuracy: Low
        $x_1_6 = {00 ff c0 0a c7 [0-8] c0 14 00 88 [0-8] 00 87 00 39 [0-8] 00 38 c0 0f [0-8] c0 05 00 84 [0-8] 00 35 c0 07 [0-8] c0}  //weight: 1, accuracy: Low
        $x_1_7 = {c0 0a c0 14 [0-8] 00 88 00 87 [0-8] 00 39 00 38 [0-8] c0 0f c0 05 [0-8] 00 84 00 35 [0-8] c0 07 c0 09 [0-8] c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Autophyte_B_2147724707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.B!dha"
        threat_id = "2147724707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 88 9c 24 ?? ?? ?? ?? c6 ?? ?? ?? ?? ?? ?? 35 88 ?? ?? ?? ?? ?? ?? c6 ?? ?? ?? ?? ?? ?? 05 88 ?? ?? ?? ?? ?? ?? c6 ?? ?? ?? ?? ?? ?? 0a 88 ?? ?? ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? ?? c6}  //weight: 1, accuracy: Low
        $x_1_2 = {04 88 5c 24 ?? c6 ?? ?? ?? 05 88 ?? ?? ?? c6 ?? ?? ?? 0a 88 ?? ?? ?? c6 ?? ?? ?? 09 88 ?? ?? ?? c6 ?? ?? ?? 64 88 ?? ?? ?? c6}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 88 44 24 ?? c6 [0-6] 0a 88 [0-6] c6 [0-6] 14 88 [0-6] c6 [0-6] 88 88 [0-6] c6 [0-6] 87 88 5c 24 4e c6}  //weight: 1, accuracy: Low
        $x_1_4 = {0a 88 84 24 ?? ?? ?? ?? c6 ?? ?? ?? ?? ?? ?? 14 88 ?? ?? ?? ?? ?? ?? c6 ?? ?? ?? ?? ?? ?? 88 88 ?? ?? ?? ?? ?? ?? c6 ?? ?? ?? ?? ?? ?? 87 88 ?? ?? ?? ?? ?? ?? c6 ?? ?? ?? ?? ?? ?? 39 88 ?? ?? ?? ?? ?? ?? 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Autophyte_C_2147724708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.C!dha"
        threat_id = "2147724708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {da c6 44 24 ?? e1 c6 [0-6] 61 c6 [0-6] ff c6 [0-6] 0c c6 [0-6] 27 c6 [0-6] 95 c6 [0-6] 87 c6 [0-6] 17 c6}  //weight: 4, accuracy: Low
        $x_4_2 = {da c6 84 24 ?? ?? ?? ?? e1 c6 [0-6] 61 c6 [0-6] ff c6 [0-6] 0c c6 [0-6] 27 c6 [0-6] 95 c6 [0-6] 87 c6 [0-6] 17 c6}  //weight: 4, accuracy: Low
        $x_4_3 = {ff 50 c6 45 ?? da c6 ?? ?? e1 c6 ?? ?? 61 c6 ?? ?? ff c6 ?? ?? 0c c6 ?? ?? 27 c6 ?? ?? 95 c6 ?? ?? 87 c6}  //weight: 4, accuracy: Low
        $x_4_4 = {ff 51 c6 45 ?? da c6 ?? ?? e1 c6 ?? ?? 61 c6 ?? ?? ff c6 ?? ?? 0c c6 ?? ?? 27 c6 ?? ?? 95 c6 ?? ?? 87 c6}  //weight: 4, accuracy: Low
        $x_4_5 = {ff 52 c6 45 ?? da c6 ?? ?? e1 c6 ?? ?? 61 c6 ?? ?? ff c6 ?? ?? 0c c6 ?? ?? 27 c6 ?? ?? 95 c6 ?? ?? 87 c6}  //weight: 4, accuracy: Low
        $x_4_6 = {ff 53 c6 45 ?? da c6 ?? ?? e1 c6 ?? ?? 61 c6 ?? ?? ff c6 ?? ?? 0c c6 ?? ?? 27 c6 ?? ?? 95 c6 ?? ?? 87 c6}  //weight: 4, accuracy: Low
        $x_4_7 = {ff 56 c6 45 ?? da c6 ?? ?? e1 c6 ?? ?? 61 c6 ?? ?? ff c6 ?? ?? 0c c6 ?? ?? 27 c6 ?? ?? 95 c6 ?? ?? 87 c6}  //weight: 4, accuracy: Low
        $x_4_8 = {ff 57 c6 45 ?? da c6 ?? ?? e1 c6 ?? ?? 61 c6 ?? ?? ff c6 ?? ?? 0c c6 ?? ?? 27 c6 ?? ?? 95 c6 ?? ?? 87 c6}  //weight: 4, accuracy: Low
        $x_1_9 = {da e1 61 ff 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_10 = {0c 27 95 87 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_11 = {17 57 a4 d6 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_12 = {ea e3 82 2b 03 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autophyte_D_2147724709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.D!dha"
        threat_id = "2147724709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 8a 7c 8e [0-6] ae 3d b4 3f [0-6] f2 e2 33 24 [0-6] 97 51 34 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autophyte_E_2147724710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.E!dha"
        threat_id = "2147724710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {af c6 44 24 [0-1] 3d c6 ?? ?? ?? 78 c6 ?? ?? ?? 23 c6 ?? ?? ?? 4a c6 ?? ?? ?? 79 c6 ?? ?? ?? 92 c6 ?? ?? ?? 81 c6 ?? ?? ?? 9d c6}  //weight: 1, accuracy: Low
        $x_1_2 = {af c6 84 24 [0-4] 3d c6 [0-6] 78 c6 [0-6] 23 c6 [0-6] 4a c6 [0-6] 79 c6 [0-6] 92 c6 [0-6] 81 c6 [0-6] 9d c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Autophyte_F_2147724711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.F!dha"
        threat_id = "2147724711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 29 2e 4c 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {5d a3 b5 d0 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {67 f0 81 b7 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_4 = {36 e5 d5 93 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_5 = {0a 91 fb f2 98 29 10 72 5f 87 5f af 09 1e 11 50}  //weight: 1, accuracy: High
        $x_1_6 = {02 84 ea cc ba 34 1c 74 49 87 78 92 0b 10 07 3e 51}  //weight: 1, accuracy: High
        $x_1_7 = {0e 9b ff db ac 2f 1f 72 6d f4}  //weight: 1, accuracy: High
        $x_1_8 = {0a 91 fb f6 8f 2b 03 47 4d 80 63 87 64}  //weight: 1, accuracy: High
        $x_1_9 = {3e 9c fa d6 8e 29 04 79 2c}  //weight: 1, accuracy: High
        $x_1_10 = {1f 91 e8 ed 9a 23 1d 5c 49 8d 4a c6}  //weight: 1, accuracy: High
        $x_1_11 = {1a a7 ce f1 9e 27 01 63 59 84 0b}  //weight: 1, accuracy: High
        $x_1_12 = {1f 91 e8 f3 9f 23 01 6e 7a 95 67 b3 01 3e 1a 11 51}  //weight: 1, accuracy: High
        $x_1_13 = {3e 9b ec c9 8f 32 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Autophyte_G_2147724712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.G!dha"
        threat_id = "2147724712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 01 3c 69 7c ?? 3c 70 7f ?? 04 09 eb ?? 3c 72 7c ?? 3c 79 7e ?? 3c 49 7c ?? 3c 50 [0-6] 3c 52 7c ?? 3c 59 7f ?? 2c 09}  //weight: 5, accuracy: Low
        $x_1_2 = "----FxivBxlwdaip" ascii //weight: 1
        $x_1_3 = "Acceyk:" ascii //weight: 1
        $x_1_4 = "NJAJkaikly" ascii //weight: 1
        $x_1_5 = "jxctek" ascii //weight: 1
        $x_1_6 = "GekKevyYakh" ascii //weight: 1
        $x_1_7 = "IeadFrue" ascii //weight: 1
        $x_1_8 = "IegQleipMaule" ascii //weight: 1
        $x_1_9 = "Yixcejj32Weok" ascii //weight: 1
        $x_1_10 = "__WSAFDIjSek" ascii //weight: 1
        $x_1_11 = "WSACueawly" ascii //weight: 1
        $x_1_12 = "WSASkaikly" ascii //weight: 1
        $x_1_13 = "ReadFrue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autophyte_H_2147724713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.H!dha"
        threat_id = "2147724713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GprFjpgyKawjpPmA" ascii //weight: 1
        $x_1_2 = "GprDepnVpyPmA" ascii //weight: 1
        $x_1_3 = "GprPnjxVpyPmA" ascii //weight: 1
        $x_1_4 = "GprFjpgyTnqdVpyA" ascii //weight: 1
        $x_1_5 = "GprCgpaipVpyA" ascii //weight: 1
        $x_1_6 = "GprthipgHpgktcpCigwSanowpgA" ascii //weight: 1
        $x_1_7 = "GprCwdhpVpy" ascii //weight: 1
        $x_1_8 = "tnpi_aoog" ascii //weight: 1
        $x_1_9 = "__LHAQOThHpi" ascii //weight: 1
        $x_1_10 = "tdciwhdcvpi" ascii //weight: 1
        $x_1_11 = "LHARpiWahiPggdg" ascii //weight: 1
        $x_1_12 = "cwdhphdcvpi" ascii //weight: 1
        $x_1_13 = "LHAHiagije" ascii //weight: 1
        $x_1_14 = "LHACwpanje" ascii //weight: 1
        $x_1_15 = "RpiWdrtcawOgtkph" ascii //weight: 1
        $x_1_16 = "CgpaipEgdcphhA" ascii //weight: 1
        $x_1_17 = "RpiIpxeEaisA" ascii //weight: 1
        $x_1_18 = "CgpaipIddwspwe32Hnaehsdi" ascii //weight: 1
        $x_1_19 = "HpiQtwpEdtnipg" ascii //weight: 1
        $x_1_20 = "Egdcphh32Npmi" ascii //weight: 1
        $x_1_21 = "LgtipQtwp" ascii //weight: 1
        $x_1_22 = "RpiXdojwpQtwpNaxpA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Autophyte_I_2147724714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.I!dha"
        threat_id = "2147724714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 08 fe c9 80 f9 62 88 08 7c ?? 80 f9 79 7f ?? b2 db 2a d1 88 10 8a 48 01 40 84 c9 75}  //weight: 10, accuracy: Low
        $x_1_2 = {53 77 75 73 69 68 77 6a 54 77 6a 66 73 79 77 44 68 6a 70 49 62 6e 78 70 77 6a 58 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 74 62 6e 75 77 54 77 6a 66 73 79 77 44 6d 6e 76 73 75 33 58 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 6d 6d 71 67 6c 51 6a 73 66 73 70 77 75 77 57 62 70 67 77 58 00}  //weight: 1, accuracy: High
        $x_1_5 = {58 6d 65 37 35 45 73 69 62 7a 70 77 58 6d 65 37 35 47 69 53 77 78 73 6a 77 79 68 73 6d 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {47 6a 77 77 4d 73 7a 6a 62 6a 63 00}  //weight: 1, accuracy: High
        $x_1_7 = {57 73 6a 68 67 62 70 42 70 70 6d 79 00}  //weight: 1, accuracy: High
        $x_1_8 = {44 6a 77 62 68 77 54 77 6a 66 73 79 77 58 00}  //weight: 1, accuracy: High
        $x_1_9 = {50 6c 77 6e 51 6a 6d 79 77 69 69 00}  //weight: 1, accuracy: High
        $x_1_10 = {54 77 68 47 73 70 77 51 6d 73 6e 68 77 6a 00}  //weight: 1, accuracy: High
        $x_1_11 = {47 73 6e 78 53 77 69 6d 67 6a 79 77 58 00}  //weight: 1, accuracy: High
        $x_1_12 = {58 73 6e 46 64 77 79 00}  //weight: 1, accuracy: High
        $x_1_13 = {58 54 42 44 70 77 62 6e 67 6c 00}  //weight: 1, accuracy: High
        $x_1_14 = {4e 6d 78 67 70 77 34 33 47 73 6a 69 68 58 00}  //weight: 1, accuracy: High
        $x_1_15 = {57 73 6a 68 67 62 70 51 6a 6d 68 77 79 68 46 64 00}  //weight: 1, accuracy: High
        $x_1_16 = {54 77 68 46 6a 6a 6d 6a 4e 6d 78 77 00}  //weight: 1, accuracy: High
        $x_1_17 = {48 77 68 45 6a 73 66 77 55 63 6c 77 58 00}  //weight: 1, accuracy: High
        $x_1_18 = {69 77 70 77 79 68 00}  //weight: 1, accuracy: High
        $x_1_19 = {69 74 67 68 78 6d 65 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autophyte_J_2147724715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.J!dha"
        threat_id = "2147724715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sockte" ascii //weight: 1
        $x_1_2 = "clostsockte" ascii //weight: 1
        $x_1_3 = "conntce" ascii //weight: 1
        $x_1_4 = "vtewosebjnamt" ascii //weight: 1
        $x_1_5 = "swfedohn" ascii //weight: 1
        $x_1_6 = "lxsetn" ascii //weight: 1
        $x_1_7 = "WSASearefp" ascii //weight: 1
        $x_1_8 = "stesockope" ascii //weight: 1
        $x_1_9 = "WSACltanfp" ascii //weight: 1
        $x_1_10 = "GteDrxgtTjptA" ascii //weight: 1
        $x_1_11 = "VxrefalQftrjEi" ascii //weight: 1
        $x_1_12 = "CrtaetFxltMappxnvA" ascii //weight: 1
        $x_1_13 = "FxndClost" ascii //weight: 1
        $x_1_14 = "MogtFxltEiA" ascii //weight: 1
        $x_1_15 = "GteModfltHandltA" ascii //weight: 1
        $x_1_16 = "FxndNtieFxltA" ascii //weight: 1
        $x_1_17 = "GteCompfetrNamtA" ascii //weight: 1
        $x_1_18 = "WrxetProctssMtmorj" ascii //weight: 1
        $x_1_19 = "VxrefalProetceEi" ascii //weight: 1
        $x_1_20 = "FrttLxbrarj" ascii //weight: 1
        $x_1_21 = "TtrmxnaetProctss" ascii //weight: 1
        $x_1_22 = "CrtaetFxltA" ascii //weight: 1
        $x_1_23 = "OptnProctss" ascii //weight: 1
        $x_1_24 = "GteLovxcalDrxgts" ascii //weight: 1
        $x_1_25 = "SteFxltTxmt" ascii //weight: 1
        $x_1_26 = "GteVtrsxonEiA" ascii //weight: 1
        $x_1_27 = "UnmapVxthOuFxlt" ascii //weight: 1
        $x_1_28 = "GteCfrrtneProctss" ascii //weight: 1
        $x_1_29 = "GteSjsetmDxrtceorjA" ascii //weight: 1
        $x_1_30 = "GteLocalTxmt" ascii //weight: 1
        $x_1_31 = "CrtaetProctssA" ascii //weight: 1
        $x_1_32 = "GteTtmpPaewA" ascii //weight: 1
        $x_1_33 = "CrtaetToolwtlp32Snapswoe" ascii //weight: 1
        $x_1_34 = "GteFxltAeerxbfetsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Autophyte_K_2147724716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.K!dha"
        threat_id = "2147724716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 01 3c 62 7c ?? 3c 79 7f ?? 3c 69 7c ?? 3c 70 7f ?? 04 09 eb ?? 3c 72 7c ?? 2c 09 88 01 8a 41 01 41 84 c0 75}  //weight: 10, accuracy: Low
        $x_10_2 = {41 0f b6 03 3c 62 7c ?? 3c 79 7f ?? 3c 69 7c ?? 3c 70 7f ?? 04 09 eb ?? 3c 72 7c ?? 2c 09 41 88 03 49 ff c3 41 80 3b 00 75}  //weight: 10, accuracy: Low
        $x_1_3 = "WSASkaikly" ascii //weight: 1
        $x_1_4 = "GekDirmeTpyeA" ascii //weight: 1
        $x_1_5 = "VriklauQleipEo" ascii //weight: 1
        $x_1_6 = "GekMxdlueHawdueA" ascii //weight: 1
        $x_1_7 = "FivnNmcgFixmA" ascii //weight: 1
        $x_1_8 = "GekCxvylkeiNaveA" ascii //weight: 1
        $x_1_9 = "WirkePixcejjxiMevxip" ascii //weight: 1
        $x_1_10 = "VriklauPixkeckEo" ascii //weight: 1
        $x_1_11 = "FieeLrbiaip" ascii //weight: 1
        $x_1_12 = "TeivrwakePixcejj" ascii //weight: 1
        $x_1_13 = "CieakeFrueA" ascii //weight: 1
        $x_1_14 = "OyewPixcejj" ascii //weight: 1
        $x_1_15 = "GekLxgrcauDirmej" ascii //weight: 1
        $x_1_16 = "GekCliiewkPixcejj" ascii //weight: 1
        $x_1_17 = "GekSpjkevDrieckxip" ascii //weight: 1
        $x_1_18 = "GekLxcauTrve" ascii //weight: 1
        $x_1_19 = "CieakePixcejjA" ascii //weight: 1
        $x_1_20 = "CieakeTxxuheuy32Swayjhxk" ascii //weight: 1
        $x_1_21 = "SekFruePxrwkei" ascii //weight: 1
        $x_1_22 = "ReadPixcejjMevxip" ascii //weight: 1
        $x_1_23 = "MayVrenOfFrue" ascii //weight: 1
        $x_1_24 = "GekMxdlueFrueNaveA" ascii //weight: 1
        $x_1_25 = "WirkeFrue" ascii //weight: 1
        $x_1_26 = "TeivrwakeThiead" ascii //weight: 1
        $x_1_27 = "LxadLrbiaipA" ascii //weight: 1
        $x_1_28 = "GekTevyFrueNaveA" ascii //weight: 1
        $x_1_29 = "GekFrueSrze" ascii //weight: 1
        $x_1_30 = "ReadFrue" ascii //weight: 1
        $x_1_31 = "CieakeThiead" ascii //weight: 1
        $x_1_32 = "FrwdFrijkFrueA" ascii //weight: 1
        $x_1_33 = "WrwEoec" ascii //weight: 1
        $x_1_34 = "Mxdlue32Frijk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autophyte_L_2147724717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.L!dha"
        threat_id = "2147724717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 08 80 f9 62 7c 0b 80 f9 79 7f 06 b2 db 2a d1 88 10}  //weight: 10, accuracy: High
        $x_1_2 = "WSASgaigfk" ascii //weight: 1
        $x_1_3 = "GvgDirevTbkvA" ascii //weight: 1
        $x_1_4 = "VrigfaoQfvibEc" ascii //weight: 1
        $x_1_5 = "GvgMlwfovHamwovA" ascii //weight: 1
        $x_1_6 = "FindNextFileA" ascii //weight: 1
        $x_1_7 = "GvgClnkfgviNanvA" ascii //weight: 1
        $x_1_8 = "WirgvPilxvhhMvnlib" ascii //weight: 1
        $x_1_9 = "VrigfaoPilgvxgEc" ascii //weight: 1
        $x_1_10 = "FivvLryiaib" ascii //weight: 1
        $x_1_11 = "TvinrmagvPilxvhh" ascii //weight: 1
        $x_1_12 = "CivagvFrovA" ascii //weight: 1
        $x_1_13 = "OkvmPilxvhh" ascii //weight: 1
        $x_1_14 = "GvgLltrxaoDirevh" ascii //weight: 1
        $x_1_15 = "GvgCfiivmgPilxvhh" ascii //weight: 1
        $x_1_16 = "GvgSbhgvnDrivxglibA" ascii //weight: 1
        $x_1_17 = "GvgLlxaoTrnv" ascii //weight: 1
        $x_1_18 = "CivagvPilxvhhA" ascii //weight: 1
        $x_1_19 = "CivagvTllosvok32Smakhslg" ascii //weight: 1
        $x_1_20 = "SvgFrovPlrmgvi" ascii //weight: 1
        $x_1_21 = "RvawPilxvhhMvnlib" ascii //weight: 1
        $x_1_22 = "MakVrvdOuFrov" ascii //weight: 1
        $x_1_23 = "GvgMlwfovFrovNanvA" ascii //weight: 1
        $x_1_24 = "WirgvFrov" ascii //weight: 1
        $x_1_25 = "TvinrmagvTsivaw" ascii //weight: 1
        $x_1_26 = "LlawLryiaibA" ascii //weight: 1
        $x_1_27 = "GvgTvnkFrovNanvA" ascii //weight: 1
        $x_1_28 = "GvgFrovSrzv" ascii //weight: 1
        $x_1_29 = "RvawFrov" ascii //weight: 1
        $x_1_30 = "CivagvTsivaw" ascii //weight: 1
        $x_1_31 = "FrmwFrihgFrovA" ascii //weight: 1
        $x_1_32 = "WrmEcvx" ascii //weight: 1
        $x_1_33 = "Mlwfov32Frihg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autophyte_M_2147724718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autophyte.M!dha"
        threat_id = "2147724718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autophyte"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 2a 2a 3b 00}  //weight: 1, accuracy: High
        $x_1_2 = {3a 47 59 3a 00}  //weight: 1, accuracy: High
        $x_1_3 = {3a 46 5a 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 44 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 57 53 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 4d 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {46 4d 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {57 4d 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {44 57 53 30 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

