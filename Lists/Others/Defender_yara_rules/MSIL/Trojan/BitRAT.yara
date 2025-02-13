rule Trojan_MSIL_BitRAT_BR_2147816565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.BR!MTB"
        threat_id = "2147816565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 6a 01 00 0a 72 ?? ?? ?? ?? 6f 6b 01 00 0a 6f 6c 01 00 0a 0d 06 09 6f 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {28 6f 01 00 0a 13 04 28 6a 01 00 0a 06 6f 70 01 00 0a 11 ?? 16 11 ?? 8e 69 6f 71 01 00 0a 6f 72 01 00 0a 0c 02}  //weight: 1, accuracy: Low
        $x_1_3 = {08 28 6f 01 00 0a 28 76 01 00 0a 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_PBA_2147827836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.PBA!MTB"
        threat_id = "2147827836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 38 8b d8 ff 15 8d ?? ?? ?? 66 89 b7 fe 07 00 00 85 db}  //weight: 1, accuracy: Low
        $x_1_2 = {44 89 6c 24 30 c7 44 24 3c 02 00 00 00 4c 89 7c 24 20 ff 15 ?? ?? ?? 00 41 8b cd e8 dd}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 55 66 ff 15 ?? ?? ?? 00 48 89 05 db 2e 02 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 0d 8a 59 02 00 e8 ?? ?? ?? 00 ff 15 87 50 00 00 48 8d 1d}  //weight: 1, accuracy: Low
        $x_1_5 = {48 ff 25 42 17 00 00 cc cc 48 89 5c 24 08 57 48 83 ec 30 33 db 4c 8d 4c 24 58 48 89 5c 24 20 41 8b f8 ff 15 ?? ?? ?? 00 85 c0 74 0b 3b 7c 24 58 75 05 bb 01 00 00 00 8b c3 48 8b 5c 24 40 48 83 c4 30 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_ABFZ_2147837425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.ABFZ!MTB"
        threat_id = "2147837425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1e 5b 6f 1d 00 00 0a 6f 20 00 00 0a 06 17 6f 21 00 00 0a 11 05 0d 07 06 6f 22 00 00 0a 17 73 23 00 00 0a 13 04 11 04 09 16 09 8e 69 6f 24 00 00 0a 17 2c f1 de 0b 11 04 6f 10 00 00 0a 16 2d f6 dc 07 6f 25 00 00 0a 13 08 16 3a 66 ff ff ff de 2e}  //weight: 2, accuracy: High
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_NAT_2147841232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.NAT!MTB"
        threat_id = "2147841232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 00 0c 00 00 28 ?? ?? 00 0a 00 73 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 0a 2b 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Loamnboa.MainWindow.resources" ascii //weight: 1
        $x_1_3 = "Hiez" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_B_2147841508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.B!MTB"
        threat_id = "2147841508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ddffrdjfffsffhgdffafcfdssfkfhgj" ascii //weight: 2
        $x_2_2 = "hdffhdfsdhdffdfkdf" ascii //weight: 2
        $x_2_3 = "fddsfffhss" ascii //weight: 2
        $x_2_4 = "fsfffafad" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_NNB_2147841596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.NNB!MTB"
        threat_id = "2147841596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 9d 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 13 09 07 11 09 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "eef2f" wide //weight: 1
        $x_1_3 = "WinForms_RecursiveFormCreate" wide //weight: 1
        $x_1_4 = "WinForms_SeeInnerException" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_NIT_2147841597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.NIT!MTB"
        threat_id = "2147841597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 8a 01 00 0a 0a 08 12 03 fe ?? ?? ?? ?? 02 12 03 16 7d ?? ?? 00 04 12 03 11 04 7d ?? ?? 00 04 09 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "add_ResourceResolve" ascii //weight: 1
        $x_1_3 = "BitRAT.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_NTB_2147842031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.NTB!MTB"
        threat_id = "2147842031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 17 58 17 2c fb 0b 07 06 8e 69 1e 2c f4 32 ca 16 3a ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp40" ascii //weight: 1
        $x_1_3 = "Sqgswympxpaekumacsvqyqi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_ABR_2147843999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.ABR!MTB"
        threat_id = "2147843999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 1b 00 7e 48 00 00 04 06 7e 48 00 00 04 06 91 20 c0 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 48 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_AB_2147844461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.AB!MTB"
        threat_id = "2147844461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 bc 05 00 70 28 60 00 00 0a 74 31 00 00 01 0a 2b 00 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = {07 8e 69 17 59 0d 16 13 04 2b 15 07 11 04 07 11 04 91 20 94 03 00 00 59 d2 9c 11 04 17 58 13 04 11 04 09 31 e6}  //weight: 1, accuracy: High
        $x_1_3 = "Engo.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_FAS_2147846146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.FAS!MTB"
        threat_id = "2147846146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {58 4a 07 8e 69 5d 91 61 28 ?? 01 00 06 03 06 1a 58 4a 1d 58 1c 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 03 8e 69 17 59 16 2d fb 6a 06 4b 17 58 6e 5a 31 95 18 2c e7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_FAT_2147846147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.FAT!MTB"
        threat_id = "2147846147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 02 8e 69 5d 7e ?? 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 02 08 1e 58 1d 59 02 8e 69 5d 91 59 20 ?? 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 02 8e 69 15 2c fc 17 59 6a 06 17 58 16 2d fb}  //weight: 5, accuracy: Low
        $x_5_2 = {03 08 03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59 20 ?? 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 03 8e 69 15 2c fc 17 59 6a 06 17 58 16 2d fb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_BitRAT_MBIB_2147889317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.MBIB!MTB"
        threat_id = "2147889317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f}  //weight: 10, accuracy: High
        $x_1_2 = "sLog.exe" wide //weight: 1
        $x_1_3 = "1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_BitRAT_NIB_2147891166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.NIB!MTB"
        threat_id = "2147891166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 72 9b 04 00 70 6f ?? ?? 00 0a 80 ?? ?? 00 04 16 0b 2b 1b 00 7e ?? ?? 00 04 07 7e ?? ?? 00 04 07 91 20 ?? ?? 00 00 59 d2 9c 00 07 17 58 0b 07 7e ?? ?? 00 04 8e 69 fe 04 0c 08 2d d7}  //weight: 5, accuracy: Low
        $x_1_2 = "Zanobe.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_C_2147891343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.C!MTB"
        threat_id = "2147891343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 13 06 7e ?? 00 00 04 11 06 08 28 ?? 00 00 06 7e ?? 00 00 04 11 06 18 28 ?? 00 00 06 7e ?? 00 00 04 11 06 18 28 ?? 00 00 06 11 06 0d}  //weight: 2, accuracy: Low
        $x_2_2 = "aspnet_wp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRAT_ABGY_2147896498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRAT.ABGY!MTB"
        threat_id = "2147896498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 11 0b 11 02 6f ?? ?? ?? 0a 1e 5b 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 38 ?? ?? ?? 00 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 13 03 38 ?? ?? ?? ff 11 01 11 02 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 09}  //weight: 2, accuracy: Low
        $x_1_2 = "Omindajnwtygkggflmulgy" wide //weight: 1
        $x_1_3 = "Ifeceyyy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

