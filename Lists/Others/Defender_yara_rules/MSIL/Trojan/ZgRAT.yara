rule Trojan_MSIL_ZgRAT_A_2147838647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.A!MTB"
        threat_id = "2147838647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0b 06 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d de}  //weight: 2, accuracy: Low
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp1.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_RDA_2147840146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.RDA!MTB"
        threat_id = "2147840146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "27a3d4c2-fe45-4455-b52e-7b6ba402e723" ascii //weight: 1
        $x_1_2 = "kernel32" ascii //weight: 1
        $x_1_3 = "LoadLibrary" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "GZipStream" ascii //weight: 1
        $x_1_8 = "Bimzjn" ascii //weight: 1
        $x_1_9 = "IO7cNQtfltKTA5vxNa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_RDB_2147844306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.RDB!MTB"
        threat_id = "2147844306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pjlfesrqojyjtuhktzbeswp" ascii //weight: 1
        $x_1_2 = "0e2f6a3564e943bb733f2bef90a3e661" ascii //weight: 1
        $x_1_3 = "31d1d6b6e5054e186a2a953670c99637" ascii //weight: 1
        $x_1_4 = "ff8d14f7abe24bc49c5fec7752fbba52" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_B_2147847022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.B!MTB"
        threat_id = "2147847022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BHHbH87.g.resources" ascii //weight: 2
        $x_2_2 = "BHHbH87.pdb" ascii //weight: 2
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NEAA_2147847436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NEAA!MTB"
        threat_id = "2147847436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dee9df0e-b31c-4e88-9cd1-ef8f591360d4" ascii //weight: 2
        $x_2_2 = "HHhHh76.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NF_2147847495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NF!MTB"
        threat_id = "2147847495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 06 00 76 6c 58 6d fe ?? ?? 00 5c fe ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 59 20 ?? ?? ?? 0b 61 fe ?? ?? 00 20 ?? ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 5f 5a}  //weight: 5, accuracy: Low
        $x_1_2 = "SX4VPBnwra" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NZA_2147848258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NZA!MTB"
        threat_id = "2147848258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0f 00 00 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0a dd ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp22.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NZA_2147848258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NZA!MTB"
        threat_id = "2147848258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0c 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 75 ?? 00 00 1b 0b 07 16 07 8e 69 28 10 00 00 0a 07}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp57.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_C_2147848523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.C!MTB"
        threat_id = "2147848523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 14 14 11 06 74}  //weight: 2, accuracy: High
        $x_2_2 = "NBNNhH873.g.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NYN_2147850317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NYN!MTB"
        threat_id = "2147850317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 0c 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 73 ?? 00 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 73 ?? 00 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 18 2d 04}  //weight: 5, accuracy: Low
        $x_1_2 = "Zhvmhop.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_E_2147850697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.E!MTB"
        threat_id = "2147850697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0d 08 73 ?? 00 00 0a 13 04 11 04 07 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 06 de}  //weight: 2, accuracy: Low
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_F_2147895010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.F!MTB"
        threat_id = "2147895010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 1f 10 11 04 16 03 8e 69 1f 10 da 28}  //weight: 2, accuracy: High
        $x_2_2 = {11 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_G_2147895225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.G!MTB"
        threat_id = "2147895225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 91 20 ?? ?? ?? 28 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 06 17 58 0a 06 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_H_2147895605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.H!MTB"
        threat_id = "2147895605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 0a 13 07 73 ?? ?? 00 0a 13 05 11 06 73 ?? ?? 00 0a 0c 08 11 07 16 73 ?? ?? 00 0a 0d 09 11 05 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_I_2147895662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.I!MTB"
        threat_id = "2147895662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {09 11 05 16 11 05 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAA_2147896399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAA!MTB"
        threat_id = "2147896399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee}  //weight: 5, accuracy: High
        $x_1_2 = "Kfeiof" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAA_2147896399_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAA!MTB"
        threat_id = "2147896399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 09 06 09 91 7e ?? 00 00 04 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_J_2147896546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.J!MTB"
        threat_id = "2147896546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 70 20 00 01 00 00 14 14 14 6f 14 00 06 13 ?? 72 ?? 00 00 70 28 ?? 00 00 06 11 ?? 8e 69 26 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_K_2147897162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.K!MTB"
        threat_id = "2147897162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 05 08 11 05 91 11 04 11 05 11 04 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_L_2147897163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.L!MTB"
        threat_id = "2147897163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 91 20 ?? ?? 00 00 28 ?? ?? 00 06 11 04 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 5d 28 ?? ?? 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_L_2147897163_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.L!MTB"
        threat_id = "2147897163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {91 61 d2 9c 0e 00 02 11 ?? 02 11 ?? 91 03 11 ?? 03 8e 69 5d}  //weight: 2, accuracy: Low
        $x_2_2 = {16 1f 20 9d 11 ?? 6f ?? 00 00 0a 13 ?? 20 0d 00 02 16 9a 17 8d ?? 00 00 01 13 ?? 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_M_2147897177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.M!MTB"
        threat_id = "2147897177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 91 20 ?? ?? ?? a1 28 ?? ?? 00 06 06 19 5d 28 ?? ?? 00 0a 61 d2 9c 06 16 2d ?? 17 58 0a 06 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_N_2147897319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.N!MTB"
        threat_id = "2147897319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 91 72 ?? ?? 00 70 11 04 72 ?? ?? 00 70 28 ?? ?? 00 0a 5d 28 ?? ?? 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_O_2147898079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.O!MTB"
        threat_id = "2147898079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_P_2147898080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.P!MTB"
        threat_id = "2147898080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 20 00 01 00 00 14 14 14 6f ?? 01 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAC_2147900003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAC!MTB"
        threat_id = "2147900003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 50 11 02 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 58 61 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_R_2147900447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.R!MTB"
        threat_id = "2147900447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a dc 07 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 2b 72 ?? 00 00 70 20 00 01 00 00 14 14 14 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_RDC_2147900570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.RDC!MTB"
        threat_id = "2147900570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 11 03 16 11 03 8e 69 6f 97 00 00 0a 13 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAD_2147900780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAD!MTB"
        threat_id = "2147900780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://1qwqewrewqweqwrqe.sbs" wide //weight: 1
        $x_1_2 = "http://www.bcmnursing.com" wide //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_T_2147900943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.T!MTB"
        threat_id = "2147900943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 18 5a 58 0a 38 ?? 00 00 00 06 07 19 5a 58 0a 38 ?? 00 00 00 06 07 1a 5a 58 0a 07 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_RDD_2147901621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.RDD!MTB"
        threat_id = "2147901621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 09 28 01 00 00 2b 28 02 00 00 2b 0d 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_U_2147901991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.U!MTB"
        threat_id = "2147901991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? 00 00 70 a2 25 18 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 19 28 ?? ?? 00 06 a2 25 1a 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 1b 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 25 1c 02 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_V_2147902190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.V!MTB"
        threat_id = "2147902190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 00 06 d0 36 00 00 02 28 ?? 01 00 06 6f ?? 00 00 0a 73 ?? 00 00 0a 80 61 00 00 04 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAF_2147902681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAF!MTB"
        threat_id = "2147902681"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 1f 30 28 ?? 00 00 2b 28 ?? 00 00 2b 13 03 38 ?? 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAG_2147902682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAG!MTB"
        threat_id = "2147902682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 04 73 ?? 00 00 0a 11 03 11 01 28 ?? 00 00 2b 28 ?? 00 00 2b 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_W_2147902982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.W!MTB"
        threat_id = "2147902982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? 00 00 70 a2 25 18 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 19 7e ?? ?? 00 04 28 ?? ?? 00 06 a2 25 1a 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 1b 20 ?? ?? 00 00 28 ?? 00 00 06 a2 25 1c 02 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NA_2147903270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NA!MTB"
        threat_id = "2147903270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 19 11 1b 58 61 11 ?? 61 d2 9c 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_SG_2147903361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.SG!MTB"
        threat_id = "2147903361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 1b 00 00 01 28 12 00 00 06 11 03 72 01 00 00 70 28 13 00 00 06 28 01 00 00 2b 28 14 00 00 06 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_SGA_2147903805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.SGA!MTB"
        threat_id = "2147903805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 aa 05 00 06 0a 06 28 41 00 00 2b 28 42 00 00 2b 0a de 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAH_2147903843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAH!MTB"
        threat_id = "2147903843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 1e 11 09 11 24 11 26 61 11 1b 19 58 61 11 2c 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_Y_2147903995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.Y!MTB"
        threat_id = "2147903995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 04 00 00 8d ?? 00 00 01 13 01 20}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 14 14 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NB_2147905149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NB!MTB"
        threat_id = "2147905149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 27 11 20 61 19 11 1d 58 61 11 32 61 d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_Z_2147905636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.Z!MTB"
        threat_id = "2147905636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 07 16 6f ?? 00 00 0a 0c 12 ?? 28 ?? 00 00 0a 0d 06 07 09 9c 07 17 58 0b 07 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_AA_2147906016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.AA!MTB"
        threat_id = "2147906016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 11 03 11 01 11 03 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAI_2147906225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAI!MTB"
        threat_id = "2147906225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0c 08 59 20 00 00 01 00 58 20 00 00 01 00 5d 0d 06 09 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAJ_2147906498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAJ!MTB"
        threat_id = "2147906498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 4e 78 9b d7 bd c9 57 9f 09 f8 19 0a 88 90 63 79 23 46 23 f9 62}  //weight: 1, accuracy: High
        $x_1_2 = {86 47 cb 7d d5 fb f4 8a 66 40 bf 84 88 c5 46 db 03 ce 14 cb f0 ac ec}  //weight: 1, accuracy: High
        $x_1_3 = "Candidate.List" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAK_2147907585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAK!MTB"
        threat_id = "2147907585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 18 5d 39 ?? 00 00 00 02 65 38 ?? 00 00 00 02 58 0a 07 17 58 0b 07 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAL_2147907619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAL!MTB"
        threat_id = "2147907619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 03 11 02 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAM_2147907918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAM!MTB"
        threat_id = "2147907918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 1d 58 1d 59 91 61 06 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_RDE_2147908022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.RDE!MTB"
        threat_id = "2147908022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 53 00 00 0a 6f 54 00 00 0a 13 05 73 55 00 00 0a 0c 02}  //weight: 2, accuracy: High
        $x_2_2 = {11 04 08 6f 58 00 00 0a 02 08 6f 59 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_AB_2147909345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.AB!MTB"
        threat_id = "2147909345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 8e 69 1f 10 da 11 02 16 1f 10 28}  //weight: 2, accuracy: High
        $x_2_2 = {02 16 11 0a 16 02 8e 69 1f 10 da 28}  //weight: 2, accuracy: High
        $x_2_3 = {02 8e 69 1f 11 da 17 d6 8d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAN_2147910959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAN!MTB"
        threat_id = "2147910959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4AAABlAG0AYQBOAGwAYQBuAHIAZQB0A" ascii //weight: 1
        $x_1_2 = "4AYQBwAG0AbwBDAAEAAQAi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_MA_2147911088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.MA!MTB"
        threat_id = "2147911088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 97 00 00 04 20 2e 01 00 00 7e 97 00 00 04 20 2e 01 00 00 93 04 5a 20 d2 00 00 00 5f 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_NZ_2147914989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.NZ!MTB"
        threat_id = "2147914989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 11 02 6f ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 13 0d 20 17 00 00 00 38 70 fd ff ff 11 0a 18 5d 3a ?? ff ff ff 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? fd ff ff 26}  //weight: 4, accuracy: Low
        $x_1_2 = "OpenPop.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_AC_2147915836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.AC!MTB"
        threat_id = "2147915836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0a 06 20 ?? ?? ?? 00 28 ?? 00 00 06 6f ?? 00 00 0a 0b d0 ?? 00 00 01 28 ?? 00 00 0a 07 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 26 07 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_AD_2147917003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.AD!MTB"
        threat_id = "2147917003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 72 ?? 00 00 70 a2 25 18 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 19 28 ?? ?? 00 0a a2 25 1a 20 ?? ?? 00 00 8c ?? 00 00 01 a2 25 1b 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 25 1c 02 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRAT_KAO_2147921793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRAT.KAO!MTB"
        threat_id = "2147921793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 1d 11 09 11 21 11 22 61 19 11 42 58 61 11 34 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

