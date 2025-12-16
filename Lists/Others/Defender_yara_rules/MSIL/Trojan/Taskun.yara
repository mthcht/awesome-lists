rule Trojan_MSIL_Taskun_AH_2147781936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AH!MTB"
        threat_id = "2147781936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 70 03 11 04 18 6f 3a 00 00 0a 28 3b 00 00 0a 28 3c 00 00 0a 04 08 6f 3d 00 00 0a 28 3e 00 00 0a 6a 61 b7 28 3f 00 00 0a 28 40 00 00 0a 13 05 07 11 05 6f 41 00 00 0a 26 08 04 6f 39 00 00 0a 17 da fe 01 13 06 11 06 2c 04}  //weight: 10, accuracy: High
        $x_3_2 = "HebrewNumberParsing" ascii //weight: 3
        $x_3_3 = "HierachicalForecasting" ascii //weight: 3
        $x_3_4 = "XOR_Decrypt" ascii //weight: 3
        $x_3_5 = "Timeseries" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MA_2147813147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MA!MTB"
        threat_id = "2147813147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xWZjqnAcC3BA9jxQLr" ascii //weight: 1
        $x_1_2 = "iJZikVDTxC" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "Rock crushes Lizard" wide //weight: 1
        $x_1_6 = "ShoU2Af6c" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MB_2147817203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MB!MTB"
        threat_id = "2147817203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 28 ?? ?? ?? 06 0c 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0d 09 74 ?? ?? ?? 1b 17 28 ?? ?? ?? 06 13 04 11 04 28 ?? ?? ?? 06 26 07 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64CharArray" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "get_WebBrowser" ascii //weight: 1
        $x_1_5 = "Create__Instance" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_RA_2147830300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.RA!MTB"
        threat_id = "2147830300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "v4_460px_Know_if_Your_Girlfriend_Is_Horny_Step_11" wide //weight: 5
        $x_5_2 = "Buni555fu_Te5555xtB555ox" wide //weight: 5
        $x_1_3 = "WinForms_RecursiveFormCreate" wide //weight: 1
        $x_1_4 = "WinForms_SeeInnerException" wide //weight: 1
        $x_1_5 = "ApplicationSettingsBase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Taskun_FAI_2147845053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.FAI!MTB"
        threat_id = "2147845053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 16 0b 2b 19 08 06 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 07 18 58 0b 07 06 6f ?? 00 00 0a fe 04 13 08 11 08 2d d8}  //weight: 3, accuracy: Low
        $x_2_2 = "Kolko_i_krzyzyk.ResourceX" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_FAJ_2147845169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.FAJ!MTB"
        threat_id = "2147845169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 16 13 04 2b 1f 00 08 07 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? ?? 00 0a 00 00 11 04 18 58 13 04 11 04 07 6f ?? 00 00 0a fe 04 13 05 11 05 2d d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PSLR_2147845310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PSLR!MTB"
        threat_id = "2147845310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 02 72 d6 07 00 70 72 d1 01 00 70 6f 5d 00 00 0a 72 da 07 00 70 72 e0 07 00 70 6f 5d 00 00 0a 13 02 38 c2 f6 ff ff 02 7b 12 00 00 04 6f 2d 00 00 0a 02 7b 2d 00 00 04 6f 2e 00 00 0a 38 24 17 00 00 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_FAN_2147845453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.FAN!MTB"
        threat_id = "2147845453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 16 0d 2b 23 00 07 09 18 6f ?? 00 00 0a 20 03 02 00 00 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d ce}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp1.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPRF_2147845660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPRF!MTB"
        threat_id = "2147845660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 07 09 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 00 09 18 58 0d 00 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d ce}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_FAT_2147845897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.FAT!MTB"
        threat_id = "2147845897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 16 0d 2b 20 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d d1}  //weight: 3, accuracy: Low
        $x_2_2 = "VendeBemVeiculos_Patterns.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABTK_2147846318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABTK!MTB"
        threat_id = "2147846318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 14 11 16 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 18 11 15 11 18 6f ?? ?? ?? 0a 00 11 16 18 58 13 16 00 11 16 11 14 6f ?? ?? ?? 0a fe 04 13 19 11 19 2d c7}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABVB_2147846518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABVB!MTB"
        threat_id = "2147846518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0d 2b 27 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 16 91 13 05 08 11 05 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d ca}  //weight: 4, accuracy: Low
        $x_1_2 = "4D5A90" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PSOC_2147847622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PSOC!MTB"
        threat_id = "2147847622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 72 86 2d 00 70 6f ?? ?? ?? 0a 72 96 2d 00 70 72 9a 2d 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 73 ?? ?? ?? 0a 0b 07 17 8d 57 00 00 01 25 16 1f 2d 9d 6f ?? ?? ?? 0a 0c 08 8e 69 8d a0 00 00 01 0d 16 13 07 2b 15 09 11 07 08 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABXQ_2147847636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABXQ!MTB"
        threat_id = "2147847636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 0d 2b 2f 11 0d 09 5d 13 0e 11 0d 09 5b 13 0f 08 11 0e 11 0f 6f ?? 00 00 0a 13 10 07 11 05 12 10 28 ?? 00 00 0a 9c 11 05 17 58 13 05 11 0d 17 58 13 0d 11 0d 09 11 04 5a 32 c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GAN_2147847720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GAN!MTB"
        threat_id = "2147847720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 09 18 7e ?? 02 00 04 28 ?? 01 00 06 1f 10 7e ?? 02 00 04 28 ?? 01 00 06 7e ?? 02 00 04 28 ?? 01 00 06 16 91 13 05 08 17 8d ?? 00 00 01 25 16 11 05 9c 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 7e ?? 02 00 04 28 ?? 01 00 06 fe 04 13 06 11 06 3a}  //weight: 3, accuracy: Low
        $x_2_2 = "QuanLyBanHang.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GAO_2147847739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GAO!MTB"
        threat_id = "2147847739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 16 0d 2b 1d 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABXW_2147847805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABXW!MTB"
        threat_id = "2147847805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0c 07 8e 69 17 da 13 06 16 13 07 2b 19 08 07 11 07 9a 1f 10 28 ?? 00 00 0a 86 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 31 e1}  //weight: 4, accuracy: Low
        $x_1_2 = "DeleteMC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABZL_2147848626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABZL!MTB"
        threat_id = "2147848626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 28 07 09 5d 13 08 07 09 5b 13 09 08 11 08 11 09 6f ?? 00 00 0a 13 0d 11 04 12 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 07 17 58 0b 07 09 11 06 5a fe 04 13 0a 11 0a 2d cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AABM_2147849005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AABM!MTB"
        threat_id = "2147849005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 12 2b 5a 00 11 0a 11 10 11 12 6f ?? 00 00 0a 13 13 11 13 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 13 14 11 14 2c 2f 00 11 0b 12 13 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 12 13 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 12 13 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 00 11 12 17 d6 13 12}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AACJ_2147849356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AACJ!MTB"
        threat_id = "2147849356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 08 2b 2c 00 08 11 05 11 07 58 11 06 11 08 58 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 07 09 11 0a 9c 09 17 58 0d 00 11 08 17 58 13 08 11 08 17 fe 04 13 0b 11 0b 2d c9}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AACM_2147849424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AACM!MTB"
        threat_id = "2147849424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 08 2b 2a 08 11 05 11 07 58 11 06 11 08 58 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 07 09 11 0a 9c 09 17 58 0d 11 08 17 58 13 08 11 08 17 32 d1}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASAS_2147849443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASAS!MTB"
        threat_id = "2147849443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "5Z5474AQE754G7AT288FD5" wide //weight: 2
        $x_2_2 = {52 00 69 00 76 00 65 00 72 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e}  //weight: 2, accuracy: High
        $x_1_3 = "Description.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AACQ_2147849523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AACQ!MTB"
        threat_id = "2147849523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 08 2b 2c 00 09 11 05 11 07 58 11 06 11 08 58 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 08 07 11 0a 9c 07 17 58 0b 00 11 08 17 58 13 08 11 08 17 fe 04 13 0b 11 0b 2d c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASAT_2147849597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASAT!MTB"
        threat_id = "2147849597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 00 30 00 42 00 30 00 37 00 30 00 37 00 35 00 41 00 31 00 41 00 35 00 41 00 30 00 43 00 30 00 38 00 38 00 44 00 32 00 36 00 3a 00 3a 00 30 00 31 00 30 00 44 00 31 00 36 00 31 00 33 00 30 00 36 00 32 00 42 00 34 00 36}  //weight: 1, accuracy: High
        $x_1_2 = "A7311::0A0B078:1::04:7E01::040C2B" wide //weight: 1
        $x_1_3 = {30 00 39 00 31 00 37 00 35 00 38 00 30 00 44 00 30 00 39 00 30 00 37 00 46 00 45 00 30 00 34 00 31 00 33 00 30 00 37 00 31 00 31 00 30 00 37 00 32 00 44 00 43 00 31 00 30 00 38 00 31 00 33 00 30 00 38 00 32 00 42}  //weight: 1, accuracy: High
        $x_1_4 = {42 00 3a 00 34 00 36 00 43 00 30 00 32 00 3a 00 3a 00 30 00 31 00 3a 00 35 00 33 00 3a 00 37 00 34 00 3a 00 37 00 32 00 3a 00 36 00 39 00 3a 00 36 00 45 00 3a 00 36 00 37 00 3a 00 34 00 36 00 3a 00 36 00 39 00 3a 00 36 00 43 00 3a 00 36 00 35 00 3a 00 34 00 39 00 3a 00 36 00 45 00 3a 00 36 00 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AACX_2147849612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AACX!MTB"
        threat_id = "2147849612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 29 11 06 06 08 58 07 09 58 6f ?? 00 00 0a 13 0e 12 0e 28 ?? 00 00 0a 13 09 11 05 11 04 11 09 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0a 11 0a 2d cd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AADO_2147849979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AADO!MTB"
        threat_id = "2147849979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 05 2b 22 00 06 11 05 18 6f ?? 00 00 0a 13 06 07 11 05 18 5b 11 06 1f 10 28 ?? 00 00 0a 9c 00 11 05 18 58 13 05 11 05 06 6f ?? 00 00 0a fe 04 13 07 11 07 2d ce}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AADP_2147849984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AADP!MTB"
        threat_id = "2147849984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 06 2b 22 00 07 11 06 18 6f ?? 00 00 0a 13 07 08 11 06 18 5b 11 07 1f 10 28 ?? 00 00 0a 9c 00 11 06 18 58 13 06 11 06 07 6f ?? 00 00 0a fe 04 13 08 11 08 2d ce}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAEA_2147850151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAEA!MTB"
        threat_id = "2147850151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 2b 22 00 06 11 04 18 6f ?? 00 00 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 ?? 00 00 0a 9c 00 11 04 18 58 13 04 11 04 06 6f ?? 00 00 0a fe 04 13 06 11 06 2d ce}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAEN_2147850704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAEN!MTB"
        threat_id = "2147850704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 09 2b 22 00 07 11 09 18 6f ?? 00 00 0a 13 0a 08 11 09 18 5b 11 0a 1f 10 28 ?? 00 00 0a 9c 00 11 09 18 58 13 09 11 09 07 6f ?? 00 00 0a fe 04 13 0b 11 0b 2d ce}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SK_2147850741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SK!MTB"
        threat_id = "2147850741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 18 6f ?? ?? ?? 0a 13 07 08 07 18 5b 11 07 1f 10 28 ?? ?? ?? 0a 9c 07 18 58 0b 07 06 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KBA_2147850834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KBA!MTB"
        threat_id = "2147850834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "50045||4C001003|7BF294" wide //weight: 10
        $x_10_2 = "64652E00D00D00A24" wide //weight: 10
        $x_1_3 = "Dodge" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAFX_2147851016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAFX!MTB"
        threat_id = "2147851016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 09 2b 34 00 09 11 04 11 08 58 17 58 17 59 11 07 11 09 58 17 58 17 59 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 00 11 09 17 fe 04 13 0c 11 0c 2d c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAGC_2147851117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAGC!MTB"
        threat_id = "2147851117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 06 2b 34 00 11 04 11 06 07 11 06 91 09 61 08 11 05 91 61 28 ?? 00 00 0a 9c 11 05 1f 15 fe 01 13 08 11 08 2c 05 16 13 05 2b 06 11 05 17 58 13 05 11 06 17 58 13 06 00 11 06 07 8e 69 17 59 fe 02 16 fe 01 13 09 11 09 2d ba}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAGG_2147851142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAGG!MTB"
        threat_id = "2147851142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 8e 69 17 da 13 1e 16 13 1f 2b 1b 11 06 11 05 11 1f 9a 1f 10 28 ?? 00 00 0a 86 6f ?? 00 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABS_2147851294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABS!MTB"
        threat_id = "2147851294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 07 09 58 08 11 04 58 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 13 08 11 06 11 05 11 08 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf 09 17 58 0d 09}  //weight: 1, accuracy: Low
        $x_1_2 = "Bitmap" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAC_2147851453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAC!MTB"
        threat_id = "2147851453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 08 11 07 17 58 13 09 11 07 20 00 b6 00 00 5d 13 0a 11 09 20 00 b6 00 00 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 11 08 5d d2 9c 00 11 07 17 58 13 07 11 07 20 00 b6 00 00 fe 04 13 10 11 10 2d 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAC_2147851453_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAC!MTB"
        threat_id = "2147851453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 08 6f 53 00 00 0a 5d 13 06 11 05 08 6f 53 00 00 0a 5b 13 07 08 72 36 01 00 70 18 18 8d ?? ?? ?? 01 25 16 11 06 8c ?? ?? ?? 01 a2 25 17 11 07 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a a5 19 00 00 01 13 08 12 08 28 55 00 00 0a 13 09 07 11 09 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 08 6f 53 00 00 0a 08 6f 57 00 00 0a 5a fe 04 13 0a 11 0a 2d 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAE_2147851454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAE!MTB"
        threat_id = "2147851454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 0f 50 02 70 72 15 50 02 70 6f 65 00 00 0a}  //weight: 2, accuracy: High
        $x_2_2 = {08 11 05 07 11 05 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SL_2147851872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SL!MTB"
        threat_id = "2147851872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 07 11 12 07 8e 69 5d 07 11 12 07 8e 69 5d 91 08 11 12 1f 16 5d 6f 41 00 00 0a 61 28 42 00 00 0a 07 11 12 17 58 07 8e 69 5d 91 28 43 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 44 00 00 0a 9c 00 11 12 15 58 13 12 11 12 16 fe 04 16 fe 01 13 13 11 13 2d a8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAF_2147851982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAF!MTB"
        threat_id = "2147851982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 6f c0 00 00 0a 5d 13 06 09 08 6f c0 00 00 0a 5b 13 07 08 72 d5 09 00 70 18 18 8d ?? ?? ?? 01 25 16 11 06 8c ?? ?? ?? 01 a2 25 17 11 07 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a a5 33 00 00 01 13 08 12 08 28 c2 00 00 0a 13 09 07 11 09 6f c3 00 00 0a 00 09 17 58 0d 00 09 08 6f c0 00 00 0a 08 6f c4 00 00 0a 5a fe 04 13 0a 11 0a 2d 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASCP_2147852295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASCP!MTB"
        threat_id = "2147852295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 09 8e 69 5d 09 11 07 09 8e 69 5d 91 11 04 11 07 1f 16 5d 28 ?? 00 00 06 61 28 ?? 00 00 06 09 11 07 17 58 09 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 06 9c}  //weight: 1, accuracy: Low
        $x_1_2 = "Airplane_Travelling.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAG_2147852357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAG!MTB"
        threat_id = "2147852357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 74 ce 03 70 72 78 ce 03 70 6f 53 00 00 0a 72 7e ce 03 70 72 01 00 00 70}  //weight: 2, accuracy: High
        $x_2_2 = {11 04 11 09 18 6f ?? ?? ?? 0a 13 0a 11 05 11 09 18 5b 11 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 09 18 58 13 09 11 09 11 04 6f ?? ?? ?? 0a fe 04 13 0b 11 0b 2d ca}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAH_2147852358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAH!MTB"
        threat_id = "2147852358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 11 04 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d ac}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAH_2147852358_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAH!MTB"
        threat_id = "2147852358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 11 05 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d ac}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAI_2147852359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAI!MTB"
        threat_id = "2147852359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 11 04 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 11 04 15 58 13 04 11 04 16 2f b7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAC_2147852430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAC!MTB"
        threat_id = "2147852430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 09 11 04 11 22 58 11 21 11 23 58 6f ?? ?? 00 0a 13 24 12 24 28 ?? ?? 00 0a 13 25 08 07 11 25 9c 07 17 58 0b 11 23 17 58 13 23 00 11 23 17 fe 04 13 26 11 26 2d c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAD_2147852435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAD!MTB"
        threat_id = "2147852435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 07 11 12 07 8e 69 5d 07 11 12 07 8e 69 5d 91 08 11 12 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 11 12 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 ?? ?? 00 00 58 20 ?? ?? 00 00 5d 28 ?? 00 00 0a 9c 00 11 12 15 58 13 12 11 12 16 fe 04 16 fe 01 13 13 11 13 2d a8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAJ_2147852683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAJ!MTB"
        threat_id = "2147852683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 72 cb 3a 03 70 72 cf 3a 03 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 09 72 d5 3a 03 70 72 81 00 00 70 6f ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 18 5b 8d ?? ?? ?? 01 13 05 16 13 08 2b 21 00 11 05 11 08 11 04 11 08 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAK_2147852684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAK!MTB"
        threat_id = "2147852684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f ?? ?? ?? 0a 61 07 11 05 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d b6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASCQ_2147888227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASCQ!MTB"
        threat_id = "2147888227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 0d 2b 3e 00 07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 08 11 08 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAA_2147888634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAA!MTB"
        threat_id = "2147888634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 [0-15] 17 58 07 8e 69 5d 13 [0-15] 59 20 00 01 00 00 58 20 ff 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAA_2147888634_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAA!MTB"
        threat_id = "2147888634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 09 16 2f c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAMS_2147888829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAMS!MTB"
        threat_id = "2147888829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 05 1f 16 5d 28 ?? 00 00 06 d2 13 08 07 11 05 17 58 07 8e 69 5d 91 13 09}  //weight: 2, accuracy: Low
        $x_2_2 = {11 07 11 08 61 11 09 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBC_2147889346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBC!MTB"
        threat_id = "2147889346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 08 11 04 08 8e 69 5d 08 11 04 08 8e 69 5d 91 09 11 04 1f 16 5d 6f ?? ?? ?? 0a 61 08 11 04 17 58 08 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 11 04 15 58 13 04 00 11 04 16 fe 04 16 fe 01 13 07 11 07 2d b6}  //weight: 2, accuracy: Low
        $x_2_2 = "QLCHApple_BUS.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBF_2147889347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBF!MTB"
        threat_id = "2147889347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 08 09 5d 13 09 11 08 11 04 5d 13 0a 07 11 09 91 13 0b 08 11 0a 6f ?? ?? ?? 0a 13 0c 07 11 08 17 58 09 5d 91 13 0d 11 0b 11 0c 61 11 0d 59 20 00 01 00 00 58 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 00 11 08 17 59 13 08 11 08 16 fe 04 16 fe 01 13 0f 11 0f 2d a6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBG_2147889348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBG!MTB"
        threat_id = "2147889348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 09 5d 13 05 06 11 07 5d 13 0a 07 11 05 91 13 0b 11 04 11 0a 6f ?? ?? ?? 0a 13 0c 07 06 17 58 09 5d 91 13 0d 11 0b 11 0c 61 11 0d 59 20 00 01 00 00 58 13 0e 07 11 05 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d ad}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBH_2147889349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBH!MTB"
        threat_id = "2147889349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 08 09 5d 13 09 11 08 11 04 5d 13 0a 07 11 09 91 13 0b 08 11 0a 6f ?? ?? ?? 0a 13 0c 07 11 08 17 58 09 5d 91 13 0d 11 0b 11 0c 61 11 0d 59 20 00 01 00 00 58 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 11 08 17 59 13 08 11 08 16 2f b1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBJ_2147889350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBJ!MTB"
        threat_id = "2147889350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 09 11 04 5d 13 0a 11 09 11 05 5d 13 0b 08 11 0a 91 13 0c 09 11 0b 6f ?? ?? ?? 0a 13 0d 08 11 09 17 58 11 04 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 08 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAQ_2147889373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAQ!MTB"
        threat_id = "2147889373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 09 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a d2 9c 09 15 58 0d 09 16 fe 04 16 fe 01 13 07 11 07 2d ac}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAQ_2147889373_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAQ!MTB"
        threat_id = "2147889373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 cc 00 00 5d 13 09 11 08 20 00 cc 00 00 5d 13 0a 07 11 09 91 13 0b 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 11 06 1f 16 5d 91 13 0c 07 11 0a 91 11 07 58 13 0d 11 0b 11 0c 61 13 0e 07 11 09 11 0e 11 0d 11 07 5d 59 d2 9c 00 11 06 17 58 13 06 11 06 20 00 cc 00 00 fe 04 13 0f 11 0f 2d 8b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAS_2147889374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAS!MTB"
        threat_id = "2147889374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 05 11 04 5d 13 09 07 11 09 91 08 11 05 1f 16 5d 91 61 13 0a 11 0a 07 11 05 17 58 11 04 5d 91 59 20 00 01 00 00 58 13 0b 07 11 09 11 0b 20 00 01 00 00 5d d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0c 11 0c 2d b2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAS_2147889374_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAS!MTB"
        threat_id = "2147889374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 08 11 04 08 8e 69 5d 08 11 04 08 8e 69 5d 91 09 11 04 09 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 08 11 04 17 58 08 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 11 04 15 58 13 04 00 11 04 16 fe 04 16 fe 01 13 08 11 08 2d a4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAS_2147889374_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAS!MTB"
        threat_id = "2147889374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 0d 06 17 58 13 09 06 20 00 cc 00 00 5d 13 04 11 09 20 00 cc 00 00 5d 13 0a 07 11 04 91 13 0b 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 06 1f 16 5d 91 13 0c 07 11 0a 91 09 58 13 0d 11 0b 11 0c 61 13 0e 07 11 04 11 0e 11 0d 09 5d 59 d2 9c 06 17 58 0a 06 20 00 cc 00 00 fe 04 13 0f 11 0f 2d 96}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBA_2147889376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBA!MTB"
        threat_id = "2147889376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f ?? ?? ?? 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 11 09 17 59 13 09 11 09 16 2f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAZ_2147890084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAZ!MTB"
        threat_id = "2147890084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 0f 07 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 06 07 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 12 11 12 2d b0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBE_2147890085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBE!MTB"
        threat_id = "2147890085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 16 13 08 2b 4c 00 16 13 09 2b 34 00 09 11 06 11 08 58 17 58 17 59 11 07 11 09 58 17 58 17 59 6f ?? ?? ?? 0a 13 0a 12 0a 28 ?? ?? ?? 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 00 11 09 17 fe 04 13 0c 11 0c 2d c1 11 08 17 58 13 08 00 11 08 17 fe 04 13 0d 11 0d 2d a9 00 11 07 17 58 13 07 11 07 17 fe 04 13 0e 11 0e 2d 91}  //weight: 2, accuracy: Low
        $x_2_2 = "THDA_Group.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBK_2147890532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBK!MTB"
        threat_id = "2147890532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 21 01 00 70 6f ?? ?? ?? 0a 72 31 01 00 70 72 37 01 00 70 6f ?? ?? ?? 0a 72 3b 01 00 70 72 41 01 00 70 6f ?? ?? ?? 0a 72 47 01 00 70 72 4b 01 00 70 6f ?? ?? ?? 0a 0b 02 07 1f f6 28 ?? ?? ?? 06 17 8d ?? ?? ?? 01 25 16 1f 7e 9d 6f ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 08 8e 69 17 da 13 08 16 13 09 2b 23 09 11 09 17 8d ?? ?? ?? 01 25 16 08 11 09 9a 1f 10 28 ?? ?? ?? 0a 86 9c 6f ?? ?? ?? 0a 11 09 17 d6 13 09 11 09 11 08 31 d7 17 8d ?? ?? ?? 01 25 16 09 6f ?? ?? ?? 0a a2 13 04 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 72 4f 01 00 70 28 ?? ?? ?? 0a 72 5f 01 00 70 72 63 01 00 70 6f ?? ?? ?? 0a 20 00 01 00 00 14 14 11 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBM_2147890533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBM!MTB"
        threat_id = "2147890533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 1a 09 5d 13 1b 11 1a 11 04 5d 13 1c 07 11 1b 91 13 1d 08 11 1c 6f ?? ?? ?? 0a 13 1e 07 11 1a 17 58 09 5d 91 13 1f 11 1d 11 1e 61 11 1f 59 20 00 01 00 00 58 13 20 07 11 1b 11 20 20 00 01 00 00 5d d2 9c 00 11 1a 17 59 13 1a 11 1a 16 fe 04 16 fe 01 13 21 11 21 2d a6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBN_2147890534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBN!MTB"
        threat_id = "2147890534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f ?? ?? ?? 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 11 0e 28 ?? ?? ?? 06 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a9}  //weight: 3, accuracy: Low
        $x_2_2 = "PermissionViewer.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBO_2147890535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBO!MTB"
        threat_id = "2147890535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0a 11 14 5d 13 17 11 0a 11 18 5d 13 1b 11 0b 11 17 91 13 1c 11 16 11 1b 6f ?? ?? ?? 0a 13 1d 11 0b 11 0a 17 58 11 14 5d 91 13 1e 11 1c 11 1d 61 11 1e 59 20 00 01 00 00 58 13 1f 11 0b 11 17 11 1f 20 00 01 00 00 5d d2 9c 11 0a 17 59 13 0a 11 0a 16 fe 04 16 fe 01 13 20 11 20 2d a2}  //weight: 2, accuracy: Low
        $x_2_2 = "QuanLyKhoHang.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBP_2147890536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBP!MTB"
        threat_id = "2147890536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f ?? ?? ?? 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a6}  //weight: 2, accuracy: Low
        $x_2_2 = "Do_an___Quan_ly_khach_san.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARBQ_2147892493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARBQ!MTB"
        threat_id = "2147892493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 06 07 8e 69 5d 13 07 11 06 08 6f ?? ?? ?? 0a 5d 13 08 07 11 07 91 13 09 08 11 08 6f ?? ?? ?? 0a 13 0a 02 07 11 06 28 ?? ?? ?? 06 13 0b 02 11 09 11 0a 11 0b 28 ?? ?? ?? 06 13 0c 07 11 07 02 11 0c 28 ?? ?? ?? 06 9c 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 0d 11 0d 2d a2}  //weight: 2, accuracy: Low
        $x_2_2 = "Battleships.MainForm.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SM_2147892529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SM!MTB"
        threat_id = "2147892529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 09 16 2f c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAC_2147892661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAC!MTB"
        threat_id = "2147892661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 09 11 04 1e da 1f 1f 5f 63 20 ?? 00 00 00 5f b4 6f ?? 00 00 0a 00 11 04 1e da 13 04 00 00 00 11 07 17 d6 13 07 11 07 11 06 6f ?? 00 00 0a fe 04 13 0d 11 0d 3a}  //weight: 1, accuracy: Low
        $x_1_2 = "2LQJF2GK3IAKRXW63CTORZGS4CNMVXHKSLUMVWQAU3ZON2GK3IAKRZGS3IAKJQW4ZDPNUA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBJV_2147892888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBJV!MTB"
        threat_id = "2147892888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 00 6f 00 61 00 64 00 00 0f 52 00 61 00 77 00 32 00 4d 00 47 00 46 00 00 0b 6a 00 59 00 2e 00 6a 00 63 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 17 49 00 6e 00 70 00 75}  //weight: 1, accuracy: High
        $x_1_2 = "8573-3e16c7f38a59" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_NT_2147893376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.NT!MTB"
        threat_id = "2147893376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 20 40 79 1e 53 5a 20 ?? ?? ?? 2d 61 38 ?? ?? ?? ff 7e ?? ?? ?? 04 02 11 06 16 11 04 1a 59 28 ?? ?? ?? 0a 11 06 a5 ?? ?? ?? 1b 0b 11 07 20 ?? ?? ?? 65 5a 20 ?? ?? ?? f8 61 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASEQ_2147893817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASEQ!MTB"
        threat_id = "2147893817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = "Hierarchy.Sample.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMBA_2147894626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMBA!MTB"
        threat_id = "2147894626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 11 04 5d 13 09 11 08 11 05 5d 13 0a 11 08 17 58 11 04 5d 13 0b 07 11 09 91 08 11 0a 91 61 13 0c 20 00 01 00 00 13 0d 11 0c 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0f 11 0f 2d a9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMBA_2147894626_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMBA!MTB"
        threat_id = "2147894626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 1f 16 6a 5d d4 91 61 28 ?? 00 00 0a 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 11 07 17 6a 58 13 07 11 07 07 8e 69 17 59 09 17 58 5a 6a 31 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABAS_2147896391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABAS!MTB"
        threat_id = "2147896391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 08 11 04 07 11 04 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 05 11 05 2d d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAE_2147897561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAE!MTB"
        threat_id = "2147897561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 04 06 08 5d 13 05 06 17 58 08 5d 13 0b 07 11 0b 91 11 04 58 13 0c 07 11 05 91 13 0d 11 0d 11 07 06 1f 16 5d 91 61 13 0e 11 0e 11 0c 59 13 0f 07 11 05 11 0f 11 04 5d d2 9c 06 17 58 0a 06 08 11 08 17 58 5a fe 04 13 10 11 10 2d ae}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAA_2147897738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAA!MTB"
        threat_id = "2147897738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 10 11 08 17 58 13 17 11 08 11 0e 5d 13 11 11 17 11 0e 5d 13 18 11 0d 11 18 91 11 10 58 13 19 11 0d 11 11 91 13 1a 11 1a 11 13 11 08 1f 16 5d 91 61 13 1b 11 1b 11 19 59 13 1c 11 0d 11 11 11 1c 11 10 5d d2 9c 11 08 17 58 13 08 11 08 11 0e 11 14 17 58 5a fe 04 13 1d 11 1d 2d 9e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAF_2147898109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAF!MTB"
        threat_id = "2147898109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 05 06 17 58 13 0b 06 09 5d 13 06 11 0b 09 5d 13 0c 08 11 0c 91 11 05 58 13 0d 08 11 06 91 13 0e 11 0e 11 07 06 1f 16 5d 91 61 13 0f 11 0f 11 0d 59 13 10 08 11 06 11 10 11 05 5d d2 9c 06 17 58 0a 06 09 11 08 17 58 5a 32 b0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBFQ_2147899005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBFQ!MTB"
        threat_id = "2147899005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 0d 28 ?? ?? ?? ?? 14 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 17 8d ?? ?? ?? ?? 25 16 11 ?? 28 ?? ?? ?? ?? a2 14 14 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBFQ_2147899005_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBFQ!MTB"
        threat_id = "2147899005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1f 16 5d 91 13 ?? 11 ?? 11 ?? 61 13 ?? 11 ?? 11 ?? 59 13}  //weight: 1, accuracy: Low
        $x_1_2 = {07 06 8e 69 5d 06 07 06 8e 69 5d 91 08 07 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 06 07 17 58 06 8e 69 5d 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Taskun_AMBD_2147899026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMBD!MTB"
        threat_id = "2147899026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 06 16 06 8e 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARA_2147899495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARA!MTB"
        threat_id = "2147899495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 06 08 58 17 58 17 59 07 09 58 17 58 17 59 6f ?? ?? ?? 0a 13 10 12 10 28 ?? ?? ?? 0a 13 0a 11 05 11 04 11 0a 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0b 11 0b 2d c5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAD_2147899496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAD!MTB"
        threat_id = "2147899496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 05 2b 2d 07 11 04 11 05 6f 2a 00 00 0a 13 08 07 11 04 11 05 6f 2a 00 00 0a 13 09 11 09 28 2b 00 00 0a 13 0a 09 08 11 0a d2 9c 11 05 17 58 13 05 11 05 07 6f 2c 00 00 0a 32 c9 08 17 58 0c 11 04 17 58 13 04 11 04 07 6f 2d 00 00 0a 32 b0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAD_2147899496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAD!MTB"
        threat_id = "2147899496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 3a 01 00 5d 13 09 11 08 20 00 3a 01 00 5d 13 0a 07 11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 09 11 0e 11 0b 59 11 07 5d d2 9c 00 11 06 17 58 13 06 11 06 20 00 3a 01 00 fe 04 13 0f 11 0f 2d 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAU_2147899609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAU!MTB"
        threat_id = "2147899609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 08 11 08 2d b5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ATA_2147900353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ATA!MTB"
        threat_id = "2147900353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 0a 2b 21 00 02 04 06 6f ?? 00 00 0a 0b 05 03 6f ?? 00 00 0a 59 0c 03 07 08 28 ?? 00 00 06 00 00 06 17 58 0a}  //weight: 3, accuracy: Low
        $x_2_2 = {1e 62 60 0f 01 28 ?? 00 00 0a 60 13 06 02 19 8d ?? 00 00 01 25 16 11 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 06 20 ff 00 00 00 5f d2 9c 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ATA_2147900353_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ATA!MTB"
        threat_id = "2147900353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Maps_Router.DangNhap" ascii //weight: 1
        $x_1_2 = "e194105a-b04e-4388-81c9-a6bd3723b4a2" ascii //weight: 1
        $x_1_3 = "73EEBCBF0F34ABD137988DD098ACB60B9F89BF02680D023A7E18208DE554C579" ascii //weight: 1
        $x_1_4 = "Maps_Router.AboutBox1.resources" ascii //weight: 1
        $x_1_5 = "Maps_Router.DangKy.resources" ascii //weight: 1
        $x_1_6 = "Maps_Router.ManHinhChinh.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAG_2147900777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAG!MTB"
        threat_id = "2147900777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAO_2147900819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAO!MTB"
        threat_id = "2147900819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 0d 06 17 58 13 0a 06 20 00 9a 01 00 5d 13 04 11 0a 20 00 9a 01 00 5d 13 0b 07 11 04 91 13 0c 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 06 1f 16 5d 91 13 0d 07 11 0b 91 09 58 13 0e 11 0c 11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 04 11 10 09 5d d2 9c 06 17 58 0a 06 11 06 fe 04 13 11 11 11 2d 95}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAF_2147900950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAF!MTB"
        threat_id = "2147900950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 08 91 08 11 05 1f 16 5d 91 61 13 09 11 09 07 11 05 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAF_2147900950_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAF!MTB"
        threat_id = "2147900950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 [0-15] 61 [0-30] 17 58 [0-15] 08 5d 91 13 [0-20] 20 00 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAI_2147901078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAI!MTB"
        threat_id = "2147901078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5913072BAC027B02" wide //weight: 1
        $x_1_2 = "0A0D11081F2B9320A61E" wide //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAT_2147901379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAT!MTB"
        threat_id = "2147901379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 09 5d 13 08 07 11 08 91 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 11 04 1f 16 5d 91 61 13 09 11 09 07 11 04 17 58 09 5d 91 59 20 00 01 00 00 58 13 0a 07 11 08 11 0a 20 00 01 00 00 5d d2 9c 11 04 17 58 13 04 11 04 09 08 17 58 5a 32 af}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAT_2147901379_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAT!MTB"
        threat_id = "2147901379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 13 05 11 04 17 58 11 04 20 00 56 01 00 5d 13 06 20 00 56 01 00 5d 13 07 07 11 06 91 13 08 07 11 06 11 08 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 11 04 1f 16 5d 91 61 07 11 07 91 11 05 58 11 05 5d 59 d2 9c 11 04 17 58 13 04 11 04 20 00 56 01 00 32 a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARAT_2147901379_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARAT!MTB"
        threat_id = "2147901379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 06 11 05 17 58 13 07 11 05 20 00 1e 01 00 5d 13 08 11 07 20 00 1e 01 00 5d 13 09 06 11 08 91 13 0a 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 11 05 1f 16 5d 91 13 0b 06 11 09 91 11 06 58 13 0c 06 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 11 05 20 00 1e 01 00 fe 04 13 0d 11 0d 2d 8f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPCC_2147901463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPCC!MTB"
        threat_id = "2147901463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c 00 11 06 17 58 13 06}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPCX_2147901496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPCX!MTB"
        threat_id = "2147901496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAH_2147901600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAH!MTB"
        threat_id = "2147901600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 11 0d 91 11 02 11 05 1f 16 5d 91 61 13 09}  //weight: 5, accuracy: High
        $x_5_2 = {11 09 11 01 11 05 17 58 11 04 5d 91 59 20 00 ?? 00 00 58 20 00 ?? 00 00 5d 13 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAJ_2147901604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAJ!MTB"
        threat_id = "2147901604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 1f 16 5d 91 61 13 09}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPZZ_2147901622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPZZ!MTB"
        threat_id = "2147901622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5d 59 d2 9c 00 11 06 17 58 13 06 11 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPCJ_2147901822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPCJ!MTB"
        threat_id = "2147901822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0b 91 61 07 11 09 91 11 06 58 11 06 5d 59 d2 9c 00 11 05 17 58 13 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPDD_2147901909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPDD!MTB"
        threat_id = "2147901909"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {91 11 06 58 11 06 5d 59 d2 9c 00 11 05 17 58 13 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_NB_2147902553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.NB!MTB"
        threat_id = "2147902553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 59 d2 9c 06 17 58 0a 06 20 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAK_2147902738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAK!MTB"
        threat_id = "2147902738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 13 ?? 11 ?? 06 07 17 58 08 5d 91 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPXN_2147902747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPXN!MTB"
        threat_id = "2147902747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5d 91 61 13 0a 11 0a 07 11 04 17 58 09 5d 91 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 13 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPXM_2147902748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPXM!MTB"
        threat_id = "2147902748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 91 11 0b 61 13 0c 07 11 09 07 8e 69 5d 91 13 0d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMBE_2147902840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMBE!MTB"
        threat_id = "2147902840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 91 61 06 07 17 58 09 5d 91 59 20 00 01 00 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMBE_2147902840_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMBE!MTB"
        threat_id = "2147902840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 6a 5d d4 91 61 [0-14] 6a 5d d4 91 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMBE_2147902840_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMBE!MTB"
        threat_id = "2147902840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 05 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 11 ?? 61 13 ?? 07 11 ?? 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAL_2147902848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAL!MTB"
        threat_id = "2147902848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 06 8e 69 5d 91 11 ?? 61 13 ?? 06 11 ?? 06 8e 69 5d 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBFU_2147902852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBFU!MTB"
        threat_id = "2147902852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4D5A9**3***04***FFFF**B8*******4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBFV_2147903138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBFV!MTB"
        threat_id = "2147903138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 11 0f 11 0e 11 0f 8e 69 6a 5d d4 91 61}  //weight: 1, accuracy: High
        $x_1_2 = {5d d4 91 61 28 ?? 00 00 0a 07 06 17 6a 58 11 05 6a 5d d4 91 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Taskun_MBFV_2147903138_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBFV!MTB"
        threat_id = "2147903138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 20 00 00 0d 20 00 4c 00 6f 00 61 00 64}  //weight: 10, accuracy: High
        $x_1_2 = "Split" ascii //weight: 1
        $x_1_3 = "ToByte" ascii //weight: 1
        $x_1_4 = "Substring" ascii //weight: 1
        $x_1_5 = "StringToByteArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EYAA_2147903186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EYAA!MTB"
        threat_id = "2147903186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 10 91 11 0d 58 13 13}  //weight: 1, accuracy: High
        $x_1_2 = {11 0c 1f 16 5d 91 13 12}  //weight: 1, accuracy: High
        $x_1_3 = "DBConnectionUtility.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPVG_2147903229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPVG!MTB"
        threat_id = "2147903229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 91 61 13 08 11 08 07 09 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 09}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMBC_2147903240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMBC!MTB"
        threat_id = "2147903240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 8e 69 5d 13 [0-30] 07 8e 69 5d 91 13}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPVP_2147903366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPVP!MTB"
        threat_id = "2147903366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d d4 91 61 28 ?? ?? ?? 0a 07 09 17 6a 58 08 6a 5d d4 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 09 17 6a 58 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAM_2147903628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAM!MTB"
        threat_id = "2147903628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5d d4 91 61 28 ?? 00 00 0a 07 11 ?? 08 6a 5d d4 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPDC_2147903806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPDC!MTB"
        threat_id = "2147903806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d4 91 61 28 ?? ?? ?? 0a 07 11 ?? 08 6a 5d d4 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAN_2147904377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAN!MTB"
        threat_id = "2147904377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5d d4 91 08 11 ?? d4 91 61 07 11 ?? 07 8e 69 6a 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPIP_2147904486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPIP!MTB"
        threat_id = "2147904486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {91 61 07 08 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? ?? ?? 0a 59 11 0a 58 11 0a 5d 28 ?? ?? ?? 0a 9c 08 17 6a 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPPO_2147904582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPPO!MTB"
        threat_id = "2147904582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {d4 91 61 06 07 17 6a 58 06 8e 69 6a 5d d4 91}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPPG_2147904838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPPG!MTB"
        threat_id = "2147904838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 11 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0b 07 11 09 11 08 6a 5d d4 11 0b 28 ?? ?? ?? 0a 9c 11 09 17 6a 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMC_2147904928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMC!MTB"
        threat_id = "2147904928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 5d d4 91 07 06 69 1f ?? 5d 6f ?? 00 00 0a 61 11 ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 ?? 08 06 09 6a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBZP_2147905120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBZP!MTB"
        threat_id = "2147905120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d d4 91 08 11 ?? 69 1f ?? 5d 6f ?? ?? ?? 0a 13 ?? 11 ?? 61 11 ?? 59 13 ?? 11 ?? 20 00 01 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPPX_2147905146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPPX!MTB"
        threat_id = "2147905146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 09 6a 5d d4 11 ?? 28 ?? ?? ?? 0a 9c 06 17 6a 58 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_NC_2147905366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.NC!MTB"
        threat_id = "2147905366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 26 61 19 11 20 58 61 11 34 61 d2 9c 17 11 0b}  //weight: 5, accuracy: High
        $x_5_2 = {d4 91 07 06 69 1f 16 5d ?? ?? 00 00 0a 61 11 0c 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SZZP_2147905550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SZZP!MTB"
        threat_id = "2147905550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 11 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASER_2147906077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASER!MTB"
        threat_id = "2147906077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 17 58 13 ?? 07 11 ?? 07 8e 69 5d 91 13 ?? 09 06 1f 16 5d 91 13 ?? 07 06 07 06 91 11 ?? 61 11 ?? 59 20 00 01 00 00 58 d2 9c 06 17 58 0a 06 07 8e 69 fe 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SDFB_2147906170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SDFB!MTB"
        threat_id = "2147906170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 11 13 07 11 13 91 11 16 61 11 15 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMF_2147906375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMF!MTB"
        threat_id = "2147906375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e 69 5d 91 13 [0-30] 59 20 00 01 00 00 58 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMF_2147906375_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMF!MTB"
        threat_id = "2147906375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 13 ?? 02 07 11 ?? 91 11 ?? 61 07 11 ?? 91 20 ff 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMF_2147906375_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMF!MTB"
        threat_id = "2147906375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 07 11 ?? 91 13 ?? 02 11 ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 07 11 ?? 11 ?? 28 ?? 00 00 0a d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPZO_2147907400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPZO!MTB"
        threat_id = "2147907400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d 91 59 13 ?? 07 11 ?? 11 ?? 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASES_2147907454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASES!MTB"
        threat_id = "2147907454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 07 08 91 28 ?? 00 00 06 08 1f 16 5d 91 61 07 08 17 58 09 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMG_2147907601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMG!MTB"
        threat_id = "2147907601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 07 11 [0-10] 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMH_2147907705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMH!MTB"
        threat_id = "2147907705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 07 11 [0-5] 91 59 20 00 01 00 00 58 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMH_2147907705_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMH!MTB"
        threat_id = "2147907705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 13 [0-50] 1f 16 5d 91 61 07 11 ?? 91 59 20 00 01 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMMH_2147907705_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMMH!MTB"
        threat_id = "2147907705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 02 07 11 ?? 91 11 ?? 61 07 11 ?? 17 58 08 5d 91 20 ff 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAO_2147907856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAO!MTB"
        threat_id = "2147907856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 91 11 ?? 08 1f ?? 5d 91 61 07 11 ?? 91 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPNN_2147908328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPNN!MTB"
        threat_id = "2147908328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 91 61 07 11 06 91 59 20 00 01 00 00 58 13 07 1f 0b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAP_2147908992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAP!MTB"
        threat_id = "2147908992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 91 11 ?? 61 13 ?? ?? ?? 07 11 ?? 91 59 20 00 01 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAQ_2147909530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAQ!MTB"
        threat_id = "2147909530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 09 91 11 0c 61 07 11 0d 91 59 13 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAR_2147909724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAR!MTB"
        threat_id = "2147909724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 13 ?? 07 11 09 91 11 ?? 61 07 11 ?? 91 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPMP_2147910297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPMP!MTB"
        threat_id = "2147910297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d 13 0a 08 07 02 08 07 91 11 09 61 08 11 0a 91 59 28 ?? ?? 00 06 28 ?? ?? 00 ?? 9c 07 17 58 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPBM_2147910676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPBM!MTB"
        threat_id = "2147910676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {17 58 09 5d 13 0d 08 11 0b 91 11 0c 61 13 0e 08 11 0d 91 13 0f}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAE_2147910740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAE!MTB"
        threat_id = "2147910740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 13 ?? 07 11 ?? 08 5d 91 13 ?? 20 00 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAE_2147910740_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAE!MTB"
        threat_id = "2147910740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 07 11 ?? 91 13 ?? 02 11 ?? 11 ?? 59 28 ?? ?? ?? ?? 13 0a 07 11 ?? 11 ?? 28 ?? ?? ?? ?? 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPKM_2147910799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPKM!MTB"
        threat_id = "2147910799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {17 58 09 5d 13 0d 08 11 0b 91 11 0c 61 13 0e 08 11 0d 91 13 0f 02 11 0e 11 0f 59 28 ?? ?? ?? 06 13 10 08 11 0b 11 10 28 ?? ?? ?? 0a 9c 00 11}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAS_2147910860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAS!MTB"
        threat_id = "2147910860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6a 5d d4 91 58 07 06 95 58 20 ff 00 00 00 5f 0c 07 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GPAE_2147910928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GPAE!MTB"
        threat_id = "2147910928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 13 11 11 07 11 0c d4 11 11 20 ff 00 00 00 5f d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPFM_2147910936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPFM!MTB"
        threat_id = "2147910936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6a 5d d4 91 58 11 ?? 09 95 58 20 ff 00 00 00 5f 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBYN_2147911732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBYN!MTB"
        threat_id = "2147911732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d4 11 0e 6e 11 11 20 ff 00 00 00 5f 6a 61 d2 9c 11 04 17 6a 58 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPXF_2147912050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPXF!MTB"
        threat_id = "2147912050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 1b 11 18 11 09 91 13 22 11 18 11 09 11 22 11 23 61 11 1d 19 58 61 11 2c 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GPBX_2147912703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GPBX!MTB"
        threat_id = "2147912703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 6a 61 d2 9c 00 11 ?? 17 6a 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ND_2147913018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ND!MTB"
        threat_id = "2147913018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 91 09 61 07 08 17 58 07 8e 69 5d 91}  //weight: 5, accuracy: High
        $x_2_2 = "InvokeMember" ascii //weight: 2
        $x_2_3 = "ExecuteReader" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAD_2147913215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAD!MTB"
        threat_id = "2147913215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 13 ?? 07 11 ?? 11 ?? 5d 91 13 ?? 20 00 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SDXF_2147914138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SDXF!MTB"
        threat_id = "2147914138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 05 91 11 07 61 13 08 11 05 17 58 08 5d 13 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SPMF_2147915075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SPMF!MTB"
        threat_id = "2147915075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 11 0d 91 11 0e 61 13 0f 11 0d 17 58 07 8e 69 5d 13 10 07 11 10 91 13 11}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAK_2147915534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAK!MTB"
        threat_id = "2147915534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 09 91 11 ?? 61 13 ?? 09 1b 58 1a 59 08 5d 18 58 18 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAT_2147915537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAT!MTB"
        threat_id = "2147915537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 09 91 11 ?? 61 13 ?? 09 18 58 17 59 08 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAO_2147916072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAO!MTB"
        threat_id = "2147916072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 13 [0-20] 61 [0-15] 17 58 08 5d 13 [0-32] 20 00 01 00 00 58 [0-8] 20 ff 00 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAT_2147916788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAT!MTB"
        threat_id = "2147916788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5f 95 d2 61 d2 9c 11 ?? 17 6a 58 13}  //weight: 2, accuracy: Low
        $x_1_2 = {8e 69 6a 5d d4 91 58 11 [0-10] 95 58 20 ff 00 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMAU_2147916975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMAU!MTB"
        threat_id = "2147916975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 5d 08 58 08 5d 91 11 [0-5] 61 11 [0-5] 59 20 00 02 00 00 58}  //weight: 2, accuracy: Low
        $x_1_2 = {18 5a 20 00 01 00 00 5d 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SRAA_2147917041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SRAA!MTB"
        threat_id = "2147917041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 06 91 11 0d 61 11 0f 59 20 00 02 00 00 58 13 15 16 13 0a 2b 06}  //weight: 3, accuracy: High
        $x_2_2 = {11 12 11 09 5a 20 00 02 00 00 5d 26 11 09 17 58 13 09 11 09 19 fe 04 13 1e 11 1e 2d e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_NE_2147917729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.NE!MTB"
        threat_id = "2147917729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 06 17 58 08 5d 08 58 08 5d 13}  //weight: 5, accuracy: High
        $x_4_2 = {09 8e 69 5d 09 8e 69 58 09 8e 69 5d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_NG_2147918285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.NG!MTB"
        threat_id = "2147918285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "c8a6a85f-12f9-431d-a126-c94adcb9d296" ascii //weight: 3
        $x_1_2 = "kanjiToolStripMenuItem" ascii //weight: 1
        $x_1_3 = "displayFuriganaToolStripMenuItem" ascii //weight: 1
        $x_1_4 = "btnNextKanji" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SN_2147919069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SN!MTB"
        threat_id = "2147919069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 0f 91 11 10 61 11 11 59 20 00 02 00 00 58 13 12 07 11 0f 11 12 20 ff 00 00 00 5f d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SXPF_2147919101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SXPF!MTB"
        threat_id = "2147919101"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 06 11 07 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 20 00 b8 00 00 fe 04 13 09 11 09 2c 0e 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 20 00 b8 00 00 fe 04 13 0a 11 0a 2c 0e 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 11 07 17 58 13 07 11 07 07 6f ?? ?? ?? 0a fe 04 13 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SO_2147919615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SO!MTB"
        threat_id = "2147919615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 95 d2 13 10 11 0e 11 10 61 13 11 11 07 11 08 d4 11 11}  //weight: 2, accuracy: High
        $x_2_2 = "Library.LibraryForm.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SO_2147919615_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SO!MTB"
        threat_id = "2147919615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {19 8d 61 00 00 01 25 16 0f 01 28 92 00 00 0a 9c 25 17 0f 01 28 93 00 00 0a 9c 25 18 0f 01 28 94 00 00 0a 9c 0a 02 06 04}  //weight: 2, accuracy: High
        $x_2_2 = "Assignment_7.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SO_2147919615_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SO!MTB"
        threat_id = "2147919615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 91 07 28 2c 00 00 06 0d 09 2c 0f 00 06 08 8f 6f 00 00 01 28 2d 00 00 06 00 00 04 06 08 91 6f bf 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d ca}  //weight: 2, accuracy: High
        $x_2_2 = "WindowBlindsClient.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_UUAA_2147919834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.UUAA!MTB"
        threat_id = "2147919834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 09 20 00 1c 01 00 28 ?? 00 00 06 00 09 6f ?? 00 00 0a 00 00 11 07 17 58 13 07 11 07 07 6f ?? 00 00 0a fe 04 13 09 11 09 2d 9e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_NH_2147920140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.NH!MTB"
        threat_id = "2147920140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0e 11 10 61 13 11}  //weight: 5, accuracy: High
        $x_4_2 = {11 06 11 0f 20 ff 00 00 00 5f 95 d2}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAU_2147920270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAU!MTB"
        threat_id = "2147920270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f 13 [0-80] 05 95 58 20 ff 00 00 00 5f 95 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SUAA_2147920720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SUAA!MTB"
        threat_id = "2147920720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "F7H8A87554B888QJH574E2" wide //weight: 5
        $x_1_2 = "Split" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMA_2147920955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMA!MTB"
        threat_id = "2147920955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 18 fe 04 16 fe 01 0b 07 2c 0e 02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_YWAA_2147922912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.YWAA!MTB"
        threat_id = "2147922912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 09 17 58 20 ff 00 00 00 5f 13 09 11 07 11 04 11 09 95 58 20 ff 00 00 00 5f 13 07 02 11 04 11 09 8f ?? 00 00 01 11 04 11 07 8f ?? 00 00 01 28 ?? 00 00 06 00 11 04 11 09 95 11 04 11 07 95 58 20 ff 00 00 00 5f 13 11 11 06 19 5e 16 fe 01 13 12 11 12 2c 10}  //weight: 3, accuracy: Low
        $x_2_2 = {09 11 06 07 11 06 91 11 04 11 11 95 61 28 ?? 00 00 0a 9c 11 06 17 58 13 06}  //weight: 2, accuracy: Low
        $x_1_3 = "AKH45ICVA8F4B4N474PGZ4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZIAA_2147923418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZIAA!MTB"
        threat_id = "2147923418"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 06 07 28 ?? 00 00 06 0c 11 0d}  //weight: 2, accuracy: Low
        $x_3_2 = {01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06 19 8d ?? 00 00 01 25 17 17 9e 25 18 18 9e 13 07 11 0d}  //weight: 3, accuracy: Low
        $x_2_3 = {03 11 06 11 07 11 08 94 91 6f ?? 00 00 0a 00 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZMAA_2147923513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZMAA!MTB"
        threat_id = "2147923513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 18 5d 2c 0a 02 06 07 6f ?? 00 00 0a 2b 08 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 12 02 28 ?? 00 00 0a 13 04 12 02 28 ?? 00 00 0a 13 05 12 02 28 ?? 00 00 0a 13 06 19}  //weight: 3, accuracy: Low
        $x_2_2 = {03 11 07 11 0a 11 0d 94 91 6f ?? 00 00 0a 00 11 0b 11 0d 58 13 0b 00 11 0d 17 58 13 0d 11 0d 11 0c fe 04 13 0e 11 0e 2d d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZTAA_2147923751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZTAA!MTB"
        threat_id = "2147923751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 11 03 11 0e 18 5a 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 06 d2 8c 40 00 00 01 28 ?? 00 00 06 26}  //weight: 3, accuracy: Low
        $x_2_2 = {11 09 14 72 fc 04 00 70 18 8d 18 00 00 01 25 16 16 8c 03 00 00 01 a2 25 17 11 00 a2 14 14 28 ?? 00 00 06 13 0a}  //weight: 2, accuracy: Low
        $x_1_3 = {11 05 d0 40 00 00 01 28 ?? 00 00 06 28 ?? 00 00 06 74 03 00 00 1b 13 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_BH_2147925134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.BH!MTB"
        threat_id = "2147925134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {17 13 15 09 11 13 07 11 13 91 11 04 11 14 95 61 d2 9c 00 11 13 17 58 13 13 11 13 07 8e 69 fe 04}  //weight: 3, accuracy: High
        $x_2_2 = {11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PMAH_2147925521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PMAH!MTB"
        threat_id = "2147925521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0b 11 0b 1f 7b 61 20 ff 00 00 00 5f 20 ?? ?? ?? ?? 58 20 00 01 00 00 5e 26 09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 11 0a 17 58 13 0a 11 0a 07 8e 69 32 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SZDF_2147925641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SZDF!MTB"
        threat_id = "2147925641"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 2c 53 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0b 02 07 1f 10 63 20 ff 00 00 00 5f d2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SYDF_2147926031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SYDF!MTB"
        threat_id = "2147926031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 19 2f 02 2b 51 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0a 02 06 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 02 06 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 02 06 20 ff 00 00 00 5f d2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAV_2147926262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAV!MTB"
        threat_id = "2147926262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LgBkAGwAbAAAAAAANAAKAAEA" ascii //weight: 3
        $x_4_2 = "PQRMBD4EQAQ4BEIEMAQAADYACQAB" ascii //weight: 4
        $x_5_3 = "VgBlAHIAcwBpAG8AbgAAADEAM" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SVJA_2147926438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SVJA!MTB"
        threat_id = "2147926438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {95 58 20 ff 00 00 00 5f 13 0c 11 0c 1f 7b 61 20 ff 00 00 00 5f 13 0d 11 0d 20 ?? 01 00 00 58 20 00 01 00 00 5e 13 0d 11 0d 16 fe 01 13 0e 11 0e 2c 03 17 13 0d 09 11 0b 07 11 0b 91 11 04 11 0c 95 61 d2 9c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_POBH_2147926545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.POBH!MTB"
        threat_id = "2147926545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 09 11 08 58 20 ?? ?? ?? ?? 5d 13 09 11 05 17 58 20 ?? ?? ?? ?? 5f 13 05 11 09 11 08 1f 1f 5f 60 13 0a 11 0a 11 05 61 13 0a 11 06 11 04 11 05 95 58}  //weight: 6, accuracy: Low
        $x_4_2 = {09 11 08 07 11 08 91 11 04 11 0b 95 61 d2 9c 11 0c 11 0a 5a 11 08 58 20 ?? ?? ?? ?? 5d 13 0d 11 09 11 0d 61 13 09 11 08 17 58 13 08}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GSC_2147928249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GSC!MTB"
        threat_id = "2147928249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 04 03 6f ?? 00 00 0a 59 0d 09 19 32 55 12 ?? 28 ?? 00 00 0a 1f 10 62 12 ?? 28 ?? 00 00 0a 1e 62 60 12 ?? 28 ?? 00 00 0a 60 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AEHA_2147928945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AEHA!MTB"
        threat_id = "2147928945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 10 12 08 28 ?? 00 00 0a 1f 10 62 12 08 28 ?? 00 00 0a 1e 62 60 12 08 28 ?? 00 00 0a 60 13 11 11 07 11 11 61 13 07 16 13 12}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c 13 18 03 11 18 11 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PLLTH_2147930717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PLLTH!MTB"
        threat_id = "2147930717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 1f 10 62 0f 01 28 ?? 01 00 0a 1e 62 60 0f 01 28 ?? 01 00 0a 60 0b 02 19 8d ?? 00 00 01 25 16 07 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 07 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 07 20 ?? 00 00 00 5f d2 9c 6f ?? 01 00 0a 09}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ATIA_2147930805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ATIA!MTB"
        threat_id = "2147930805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 0f 01 1f 25 1f 38 28 ?? 00 00 06 9c 25 17 0f 01 20 98 03 00 00 20 86 03 00 00 28 ?? 00 00 06 9c 25 18 0f 01 20 f3 02 00 00 20 ec 02 00 00 28 ?? 00 00 06 9c 6f ?? 00 00 0a 19 0d}  //weight: 4, accuracy: Low
        $x_2_2 = {01 25 16 0f 00 20 73 01 00 00 20 6e 01 00 00 28 ?? 00 00 06 9c 25 17 0f 00 1f 09 1f 17 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 18 0c 2b a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SHLZ_2147931111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SHLZ!MTB"
        threat_id = "2147931111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 11 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 06 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_KAX_2147931294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.KAX!MTB"
        threat_id = "2147931294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 06 02 19 8d ?? 00 00 01 25 16 11 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 06 20 ff 00 00 00 5f d2 9c}  //weight: 3, accuracy: Low
        $x_2_2 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAKA_2147932020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAKA!MTB"
        threat_id = "2147932020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0b}  //weight: 3, accuracy: High
        $x_2_2 = {01 25 16 0f 00 20 f9 00 00 00 20 cf 00 00 00 28 ?? 00 00 06 9c 25 17 0f 00 20 e1 03 00 00 20 d6 03 00 00 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AEKA_2147932393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AEKA!MTB"
        threat_id = "2147932393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0b 16 0d 38}  //weight: 3, accuracy: High
        $x_2_2 = {01 25 16 0f 00 20 98 00 00 00 20 fe 00 00 00 28 ?? 00 00 06 9c 25 17 0f 00 20 b7 03 00 00 20 d0 03 00 00 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PLJBH_2147932458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PLJBH!MTB"
        threat_id = "2147932458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 0b 18 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBWQ_2147932608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBWQ!MTB"
        threat_id = "2147932608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4D5A9--3---04---FFFF--B8-------4" wide //weight: 2
        $x_1_2 = {45 00 31 00 46 00 42 00 41 00 30 00 45 00 2d 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 30 00 31 00 34 00 43 00 43 00 44 00 32 00 31 00 35 00 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PLJKH_2147932723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PLJKH!MTB"
        threat_id = "2147932723"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 28 ?? 01 00 06 08 6f ?? 00 00 0a 06 28 ?? 01 00 06 0d 28 ?? 01 00 06 09 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBR_2147932784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBR!MTB"
        threat_id = "2147932784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5f 1f 18 62 0a 06 7e ?? 00 00 04 02 17 58 91 1f 10 62 60 0a 06 7e ?? 00 00 04 02 18 58 91 1e 62 60 0a 06}  //weight: 2, accuracy: Low
        $x_1_2 = {65 6e 63 72 79 70 74 6f [0-9] 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBR_2147932784_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBR!MTB"
        threat_id = "2147932784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 04 07 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 13 04 09 11 04 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 05 06 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 08 17 58 0c 08 03 6f 7c 00 00 0a 32 b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBQ_2147932983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBQ!MTB"
        threat_id = "2147932983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 00 6c 00 00 09 4c 00 6f 00 61 00 64 00 00 23 53 00 65 00 67 00 6f 00 65 00 20 00 55 00 49 00 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_BL_2147933472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.BL!MTB"
        threat_id = "2147933472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 00 07 17 58 0b 00 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 2d}  //weight: 3, accuracy: Low
        $x_1_2 = {0d 07 08 09 28 ?? 00 00 06 00}  //weight: 1, accuracy: Low
        $x_1_3 = {07 17 58 0b 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_BM_2147933635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.BM!MTB"
        threat_id = "2147933635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 19 fe 04 16 fe 01 0b 07 2c 0c 00 02 04 28 ?? 00 00 06 00 00 2b 13 03 16 fe 02 0c 08 2c 0b 00 02 03 04 28 ?? 00 00 06 00}  //weight: 4, accuracy: Low
        $x_1_2 = {07 17 58 0b 07 03 fe 04 0c 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PHE_2147933763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PHE!MTB"
        threat_id = "2147933763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 06}  //weight: 6, accuracy: Low
        $x_5_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a}  //weight: 5, accuracy: Low
        $x_3_3 = {04 06 08 91 6f ?? 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d ca}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SP_2147934023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SP!MTB"
        threat_id = "2147934023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 1f 0a 5a 6f 6d 00 00 0a 26 04 07 08 91 6f 6e 00 00 0a 08 17 58 0c 08 03 32 e4}  //weight: 2, accuracy: High
        $x_2_2 = "MaterialWinforms.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SKEA_2147934036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SKEA!MTB"
        threat_id = "2147934036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 19 8d df 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = {0e 04 05 6f ?? 00 00 0a 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PHJ_2147934037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PHJ!MTB"
        threat_id = "2147934037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b 13}  //weight: 6, accuracy: Low
        $x_5_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b}  //weight: 5, accuracy: Low
        $x_3_3 = {04 07 08 91 6f ?? 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 0d 09}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MBS_2147934925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MBS!MTB"
        threat_id = "2147934925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 91 1f 7f 30 07 72 f3 08 00 70 2b 05 72 fd 08 00 70 0d 04 07 08 91}  //weight: 2, accuracy: High
        $x_1_2 = "SuperAdventure.Pr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_HHC_2147935204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.HHC!MTB"
        threat_id = "2147935204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 06 28 ?? 00 00 2b 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_CCJR_2147935261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.CCJR!MTB"
        threat_id = "2147935261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a [0-1] 06 28 02 00 00 2b [0-1] 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_BN_2147935430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.BN!MTB"
        threat_id = "2147935430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c}  //weight: 3, accuracy: Low
        $x_1_2 = {2b 15 03 16 fe 02 13 05 11 05 2c 0b 00 02 03 04 28}  //weight: 1, accuracy: High
        $x_1_3 = {0d 07 08 09 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SMEA_2147936213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SMEA!MTB"
        threat_id = "2147936213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 11 04}  //weight: 3, accuracy: Low
        $x_1_2 = {08 11 05 58 1f 64 5d 13 06 08 11 05 5a 1f 64 5d 13 07 08 11 05 61 1f 64 5d 13 08 02 08 11 05 6f ?? 00 00 0a 13 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAHC_2147936241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAHC!MTB"
        threat_id = "2147936241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 07 0f 00 28 77 00 00 0a 5a 1f 64 5d 9e 07 17 58 0b 07 06 8e 69 32 e7}  //weight: 5, accuracy: High
        $x_5_2 = {1f 41 08 58 d1 0d 12 03 28 7d 00 00 0a 72 0b 02 00 70 07 08 8f 56 00 00 01 28 7e 00 00 0a 28 7f 00 00 0a 13 04 04 07 08 91 6f 80 00 00 0a 08 17 58 0c 08 03 32 ca}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AJKA_2147936386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AJKA!MTB"
        threat_id = "2147936386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "4D5A9--3---04---FFFF--B8-------4-----------------------------------08----E" wide //weight: 3
        $x_2_2 = "1FBA0E-B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A24-------" wide //weight: 2
        $x_2_3 = "5045--4C0103-A39D6867--------E--2210B013--07801--04------9E9701--2---0A-1----1-02----2--04-------04" wide //weight: 2
        $x_2_4 = "--------E-1--02--47C801-03-4085--1--01----01--01------01-----------0509701-4B----" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_APOA_2147936469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.APOA!MTB"
        threat_id = "2147936469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 1b 5a 11 07 19 5a 58 20 f4 01 00 00 5d 20 c8 00 00 00 58 13 08 11 07 1f 1e 5d 1f 0a 58 13 09 08 1f 28 5d 1b 58 13 0a 02 08 11 07 6f ?? 00 00 0a 13 0b 04 03 6f ?? 00 00 0a 59 13 0c 11 0b 11 0c 03 28 ?? 00 00 06 11 07 17 58 13 07 11 07 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 a0}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ASOA_2147936577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ASOA!MTB"
        threat_id = "2147936577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 09 02 09 11 07 6f ?? 00 00 0a 13 0a 04 03 6f ?? 00 00 0a 59 13 0b 11 0a 11 0b 03 28 ?? 00 00 06 00 00 11 07 17 58 13 07 11 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 0c 11 0c 2d 92}  //weight: 3, accuracy: Low
        $x_2_2 = {09 11 07 58 1f 64 5d 13 08 11 08 1f 1e 32 14}  //weight: 2, accuracy: High
        $x_2_3 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ADPA_2147936959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ADPA!MTB"
        threat_id = "2147936959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 05 02 07 7b ?? 00 00 04 02 6f ?? 00 00 0a 58 02 6f ?? 00 00 0a 5d 11 04 7b ?? 00 00 04 02 6f ?? 00 00 0a 58 02 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 06 11 07 03 11 05 7e ?? 00 00 04 25 2d 17}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 13 04 06 7c ?? 00 00 04 28 ?? 01 00 0a 13 05 06 7c ?? 00 00 04 28 ?? 01 00 0a 13 06 04 19 8d ?? 00 00 01 25 16 11 04 9c 25 17 11 05 9c 25 18 11 06 9c 6f ?? 01 00 0a 00 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZHV_2147937123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZHV!MTB"
        threat_id = "2147937123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0a 13 05 0f 00 28 ?? 00 00 0a 13 06 0f 00 28 ?? 00 00 0a 13 07 04 19 8d ?? 00 00 01 25 16 11 05 9c 25 17 11 06 9c 25 18 11 07 9c 6f ?? 00 00 0a 00}  //weight: 6, accuracy: Low
        $x_5_2 = {0a 58 02 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAFY_2147937528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAFY!MTB"
        threat_id = "2147937528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 13 08 11 08 2d d7}  //weight: 5, accuracy: High
        $x_5_2 = {11 0b 11 0c 94 13 0d 00 11 04 11 0d 19 5a 11 0d 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 00 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 cc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SWA_2147937548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SWA!MTB"
        threat_id = "2147937548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 11 0c 94 13 0d 00 11 04 11 0d 19 5a 11 0d 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 00 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SQ_2147937550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SQ!MTB"
        threat_id = "2147937550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0f 00 28 ab 00 00 0a 16 61 d2 9c 25 17 0f 00 28 ac 00 00 0a 16 60 d2 9c 25 18 0f 00 28 ad 00 00 0a 20 ff 00 00 00 5f d2 9c}  //weight: 2, accuracy: High
        $x_2_2 = "Marksheet_Project.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAHA_2147937892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAHA!MTB"
        threat_id = "2147937892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 1f 0a 5a 6f 32 00 00 0a 26 04 07 08 91 6f 33 00 00 0a 08 17 58 0c 08 03 32 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZZI_2147937963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZZI!MTB"
        threat_id = "2147937963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 07}  //weight: 6, accuracy: Low
        $x_5_2 = {03 06 08 6f ?? 00 00 0a 0d 0e 04 0e 04 4a 17 58 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AEQA_2147937985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AEQA!MTB"
        threat_id = "2147937985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0b 74 02 00 00 1b 11 0c 94 13 0d 11 04 11 0d 19 5a 11 0d 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 11 0c 17 58 13 0c 11 0c 11 0b 74 02 00 00 1b 8e 69 32 c4}  //weight: 5, accuracy: High
        $x_2_2 = {06 74 02 00 00 1b 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 11 07 17 58 13 07 11 07 06 75 02 00 00 1b 8e 69 fe 04 13 08 11 08 2d cf}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GPPE_2147938489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GPPE!MTB"
        threat_id = "2147938489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f 00 28 d0 00 00 0a 1f 10 62 0f 00 28 d1 00 00 0a 1e 62 60 0f 00 28 d2 00 00 0a 60 0b}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GPPF_2147938490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GPPF!MTB"
        threat_id = "2147938490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 0a 08 61 11 0b 61 13 0c 11 10}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_GPPG_2147938491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.GPPG!MTB"
        threat_id = "2147938491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8e 69 5d 91 61 28 ?? ?? 00 06 02 11 01 17 58 02 8e 69 5d 91}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AVQA_2147938651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AVQA!MTB"
        threat_id = "2147938651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 04 11 05 6f ?? 00 00 0a 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 07 19 fe 04 16 fe 01 13 08 11 08 2c 2e 00 03 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 58 11 07 16 fe 02 13 09 11 09 2c 4d 00 19}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 13 0a 16 13 0b 2b 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PGTK_2147938922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PGTK!MTB"
        threat_id = "2147938922"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 20 e8 03 00 00 5d 2d 24 28 ?? 00 00 0a 08 28 ?? 00 00 0a 13 0b 12 0b 28 ?? 00 00 0a 69 13 0a 09 6c 17 11 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AZQA_2147939071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AZQA!MTB"
        threat_id = "2147939071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 7b 72 01 00 04 7b 6f 01 00 04 02 7b 71 01 00 04 03 6f ?? ?? 00 0a 0a 02 7b 72 01 00 04 7b 6c 01 00 04 02 7b 72 01 00 04 7b 6b 01 00 04 6f ?? ?? 00 0a 59 0b 07 19 fe 04 16 fe 01 0c 08 2c 39 00 02 7b 72 01 00 04 7b 6b 01 00 04 19 8d a1 00 00 01 25 16 12 00 28 ?? ?? 00 0a 9c 25 17 12 00 28 ?? ?? 00 0a 9c 25 18 12 00 28 ?? ?? 00 0a 9c 6f ?? ?? 00 0a 00 00 2b 45 07 16 fe 02 0d 09 2c 3d}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 00 28 ?? ?? 00 0a 9c 25 17 12 00 28 ?? ?? 00 0a 9c 25 18 12 00 28 ?? ?? 00 0a 9c 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AARA_2147939123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AARA!MTB"
        threat_id = "2147939123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0d 11 0d 06 7d ?? ?? 00 04 00 11 0d 02 11 0a 11 0c 6f ?? 00 00 0a 7d ?? ?? 00 04 11 0d 04 11 0d 7b ?? ?? 00 04 7b ?? ?? 00 04 6f ?? 00 00 0a 59 7d ?? ?? 00 04 7e ?? ?? 00 04 25 2d 17 26 7e ?? ?? 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? ?? 00 04 13 0e 11 0d}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 02 7c ?? ?? 00 04 28 ?? ?? 00 0a 9c 25 17 02 7c ?? ?? 00 04 28 ?? ?? 00 0a 9c 25 18 02 7c ?? ?? 00 04 28 ?? ?? 00 0a 9c 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EANM_2147939214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EANM!MTB"
        threat_id = "2147939214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 04 07 11 04 94 03 5a 1f 64 5d 9e 11 04 17 58 13 04 11 04 07 8e 69 32 e6}  //weight: 5, accuracy: High
        $x_5_2 = {07 09 07 09 94 02 5a 1f 64 5d 9e 09 17 58 0d 09 07 8e 69 32 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_BQ_2147939238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.BQ!MTB"
        threat_id = "2147939238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 17 58 8c ?? 00 00 01 6f ?? ?? 00 0a 00 38 ?? 00 00 00 11 0a 16 30 05 38 ?? 00 00 00 19 8d ?? 00 00 01 25 16 12 09 28 ?? ?? 00 0a 9c 25 17 12 09 28 ?? ?? 00 0a 9c 25 18 12 09 28 ?? ?? 00 0a 9c 13 0d 11 0a 8d ?? 00 00 01 13 0e 16 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AJRA_2147939355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AJRA!MTB"
        threat_id = "2147939355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0e 11 0e 06 7d ?? 00 00 04 00 11 0e 02 11 0b 11 0d 6f ?? 00 00 0a 7d ?? 00 00 04 11 0e 04 11 0e 7b ?? 00 00 04 7b ?? 00 00 04 6f ?? 00 00 0a 59 7d ?? 00 00 04 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 13 0f 11 0e fe ?? ?? 00 00 06 73 ?? 00 00 0a 13 10 11 0e}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 17 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 18 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_BAA_2147939507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.BAA!MTB"
        threat_id = "2147939507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 c9 00 00 0a 00 06 8e b7 18 da 16 da 17 d6 6b 28 cc 00 00 0a 5a 28 cd 00 00 0a 22 00 00 80 3f 58 6b 6c 28 ce 00 00 0a b7 13 04 08 06 11 04 93 6f cf 00 00 0a 26 00 09 17 d6 0d 09 11 05 13 06 11 06 31 bc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_BAB_2147939511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.BAB!MTB"
        threat_id = "2147939511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 8f 61 00 00 01 25 47 03 61 d2 52 07 17 58 0b 07 06 8e 69 32 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SR_2147939557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SR!MTB"
        threat_id = "2147939557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0c 94 13 0d 11 04 11 0d 6c 58 13 04 11 0c 17 58 13 0c 11 0c 11 0b}  //weight: 2, accuracy: High
        $x_2_2 = "AmirCalendar.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SR_2147939557_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SR!MTB"
        threat_id = "2147939557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 11 0d 11 0f 91 6f 96 00 00 0a 11 0e 11 0f 58 13 0e 11 0f 17 58 13 0f 11 0f 11 09 32 e2}  //weight: 2, accuracy: High
        $x_2_2 = "CalculadoraCientifica.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AMRA_2147939568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AMRA!MTB"
        threat_id = "2147939568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b 56 09 16 fe 02 13 05 11 05 2c 4c}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AVRA_2147939841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AVRA!MTB"
        threat_id = "2147939841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 07 11 0b 6f ?? 00 00 0a 13 0c 11 06 11 05 6f ?? 00 00 0a 59 13 0d 11 0d 19 fe 04 16 fe 01 13 0e 11 0e 2c 55 00 19 8d ?? 00 00 01 25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c 13 0f 08}  //weight: 5, accuracy: Low
        $x_2_2 = {11 0d 16 fe 02 13 11 11 11 2c 4e 00 19 8d ?? 00 00 01 25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_WQ_2147940040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.WQ!MTB"
        threat_id = "2147940040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 69 00 00 01 11 05 11 0a 75 48 00 00 1b 11 0c 11 07 58 11 09 59 93 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_WL_2147940104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.WL!MTB"
        threat_id = "2147940104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 17 59 91 1f 70 61 0b 02 8e 69 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SS_2147940310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SS!MTB"
        threat_id = "2147940310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 03 11 07 11 08 91 6f c7 00 00 0a 00 00 11 08 17 58 13 08 11 08 11 04 fe 04 13 09 11 09 2d e0}  //weight: 2, accuracy: High
        $x_2_2 = "WordFun.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_SS_2147940310_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.SS!MTB"
        threat_id = "2147940310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 11 4a 11 4b 91 6f e3 00 00 0a 00 17 11 42 28 db 00 00 0a 13 04 1c 8d 3c 00 00 01 25 16 72 d7 0e 00 70 a2 25 17 12 4b 28 48 00 00 0a a2 25 18 72 e9 0e 00 70 a2 25 19 12 31 28 48 00 00 0a a2 25 1a 72 e9 0e 00 70 a2 25 1b 12 35 28 48 00 00 0a a2 28 e2 00 00 0a 13 0a 00 11 4b 17 58 13 4b 11 4b 11 42 fe 04 13 4c 11 4c 2d 93}  //weight: 2, accuracy: High
        $x_2_2 = "Oyunu.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ALSA_2147940411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ALSA!MTB"
        threat_id = "2147940411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5a 69 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 19 32 4f 03 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 28 ?? 00 00 0a 13 0c 12 0c 28 ?? 00 00 0a 18 5d 17 fe 01 13 0b 11 0b 2c 06 06 17 58 0a 2b 66 06 17 59 0a 2b 60 11 09 16 31 5b 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 13 0d 16 13 0e}  //weight: 5, accuracy: Low
        $x_1_2 = {02 09 11 06 6f ?? 00 00 0a 13 07 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARSA_2147940530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARSA!MTB"
        threat_id = "2147940530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 08 5a 20 ff 00 00 00 5d 13 09 11 09 16 30 05 11 09 65 2b 02 11 09 13 09 02 11 05 11 08 6f ?? 00 00 0a 13 0a 11 05 11 08 58 18 5d 16 fe 01 13 0b 11 0b 2d 07 11 0b 16 fe 01 2b 01 17 13 0e 11 0e 2c 02 00 00 04 03 6f ?? 00 00 0a 59}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 0a 28 ?? 00 00 0a 9c 25 17 12 0a 28 ?? 00 00 0a 9c 25 18 12 0a 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_CH_2147940807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.CH!MTB"
        threat_id = "2147940807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 03 61 1f 3c 59 06 61 45 ?? ?? ?? ?? ?? ?? ?? ?? 11 05 20 ?? ?? ?? ?? 94 20 ?? ?? ?? ?? 59 0d 2b a3 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ADTA_2147940914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ADTA!MTB"
        threat_id = "2147940914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 11 04 6f ?? 00 00 0a 13 09 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 6c 07 16 9a 16 99 5a a1 25 17 12 09 28 ?? 00 00 0a 6c 07 17 9a 17 99 5a a1 25 18 12 09 28 ?? 00 00 0a 6c 07 18 9a 18 99 5a a1 13 0a 19 8d ?? 00 00 01 25 16 11 0a 16 99 d2 9c 25 17 11 0a 17 99 d2 9c 25 18 11 0a 18 99 d2 9c 13 06 00 04 03 6f ?? 00 00 0a 59 13 07 11 07 16 fe 01 13 0b 11 0b 2c 06}  //weight: 5, accuracy: Low
        $x_2_2 = {03 11 06 16 91 6f ?? 00 00 0a 00 03 11 06 17 91 6f ?? 00 00 0a 00 03 11 06 18 91 6f ?? 00 00 0a 00 00 2b 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZXW_2147940959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZXW!MTB"
        threat_id = "2147940959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 0b 02 11 0a 11 0b 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 19 fe 04 16 fe 01 13 0e 11 0e 2c 55 00 16 13 0f 11 0f 17 5f 17 fe 01 16 fe 01 13 10 11 10 2c 2e 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 0d 00 06 1e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EDL_2147941730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EDL!MTB"
        threat_id = "2147941730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 08 18 5f 17 63 13 05 2b 52 00 07 02 11 04 11 05 ?? ?? ?? ?? ?? 13 06 04 03 ?? ?? ?? ?? ?? 59 13 07 11 07 19 ?? ?? ?? ?? ?? 13 08 11 08 2c 0d 00 03 11 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EYS_2147941734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EYS!MTB"
        threat_id = "2147941734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 18 5f 17 63 13 04 2b 3f 06 02 09 11 04 ?? ?? ?? ?? ?? 13 05 04 03 ?? ?? ?? ?? ?? 59 13 06 11 06 19 ?? ?? ?? ?? ?? 2c 0a 03 11 05 ?? ?? ?? ?? ?? 2b 0f 11 06 16 31 0a 03 11 05 11 06 ?? ?? ?? ?? ?? 11 04 17 58 13 04 11 04 08 17 94 2f 09 03 ?? ?? ?? ?? ?? 04 32 b1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ATUA_2147941984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ATUA!MTB"
        threat_id = "2147941984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 12 01 28 ?? 00 00 0a 12 01 28 ?? 00 00 0a 28 ?? ?? 00 06 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 32 29 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 47 11 06 16 31 42}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 05 28 ?? 00 00 0a 9c 25 17 12 05 28 ?? 00 00 0a 9c 25 18 12 05 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAK_2147942201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAK!MTB"
        threat_id = "2147942201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 7b 06 01 00 04 11 24 11 09 91 ?? ?? ?? ?? ?? 00 00 11 09 17 58 13 09 11 09 11 16 fe 04 13 25 11 25 2d db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EM_2147942318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EM!MTB"
        threat_id = "2147942318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 07 91 06 75 03 00 00 1b 11 05 91 13 08 07 61 11 08 61 13 09 11 0d 20 c0 01 00 00 94 20 88 1a 00 00 59 13 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AJWA_2147943376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AJWA!MTB"
        threat_id = "2147943376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {12 02 25 28 ?? 00 00 0a 13 0c 11 0c 17 58 28 ?? 00 00 0a 17 13 04 1f 22 13 0e 38 ?? fb ff ff 12 02 16 28 ?? 00 00 0a 12 02 16 28 ?? 00 00 0a 15 13 04 1f 22 13 0e 38 ?? fb ff ff 12 02 28 ?? 00 00 0a 13 05 12 02 28 ?? 00 00 0a 13 06 1f 0e 13 0e 38}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 08 20 01 01 00 00 20 2f 01 00 00 28 ?? 00 00 06 9c 25 17 12 08 20 0f 02 00 00 20 20 02 00 00 28 ?? 00 00 06 9c 25 18 12 08 20 a6 02 00 00 20 96 02 00 00 28 ?? 00 00 06 9c 13 0b 11 10 1f 5c 91 11 10 19 91 59 13 0e 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AQWA_2147943830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AQWA!MTB"
        threat_id = "2147943830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 0e 11 13 6f ?? 00 00 0a 13 14 11 08 1f 64 6a 5d 3a ?? 00 00 00 72 ?? ?? 00 70 1d 8d ?? 00 00 01 25 16 11 0e 8c ?? 00 00 01 a2 25 17 11 13 8c ?? 00 00 01 a2 25 18 12 14 28 ?? 00 00 0a 8c ?? 00 00 01 a2 25 19 12 14 28 ?? 00 00 0a 8c ?? 00 00 01 a2 25 1a 12 14 28 ?? 00 00 0a 8c ?? 00 00 01 a2 25 1b 11 04 8c ?? 00 00 01 a2}  //weight: 5, accuracy: Low
        $x_2_2 = {25 1c 09 a2 28 ?? 00 00 0a 6f ?? 00 00 0a 13 10 12 10 72 ?? ?? 00 70 28 ?? 00 00 0a 13 1d 08 11 1d 6f ?? 00 00 0a 11 1d 0d 11 04 17 58 13 04 12 14 28 ?? 00 00 0a 11 0b 11 08 20 00 01 00 00 6a 5d d4 91 61 d2 13 15 12 14 28 ?? 00 00 0a 11 0b 11 08 17 6a 58 20 00 01 00 00 6a 5d d4 91 61 d2 13 16 12 14 28 ?? 00 00 0a 11 0b 11 08 18 6a 58 20 00 01 00 00 6a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EJJJ_2147943984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EJJJ!MTB"
        threat_id = "2147943984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {15 5f 13 09 11 09 06 17 17 ?? ?? ?? ?? ?? 5a 06 17 16 ?? ?? ?? ?? ?? 26 16 58 06 17 18}  //weight: 1, accuracy: Low
        $x_1_2 = {00 08 17 58 07 8e 69 5d 0c 00 11 14 17 58 13 14 11 14 11 0f fe 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EHDF_2147943986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EHDF!MTB"
        threat_id = "2147943986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 11 0e 8f 0f 00 00 01 25 71 0f 00 00 01 11 0c 11 0e 91 61 d2 81 0f 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MCD_2147944149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MCD!MTB"
        threat_id = "2147944149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 00 72 00 6d 00 20 00 43 00 61 00 73 00 74 00 00 03 20 00 00 1f 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73}  //weight: 2, accuracy: High
        $x_1_2 = {57 17 b6 09 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 ?? 00 00 00 2b 00 00 00 0d 01 00 00 41 07 00 00 cd 01 00 00 12}  //weight: 1, accuracy: Low
        $x_1_3 = {41 70 70 65 6e 64 00 67 65 74 5f 4c 65 6e 67 74 68 00 43 6c 65 61 72 00 47 65 74 50 69 78 65 6c}  //weight: 1, accuracy: High
        $x_1_4 = "StormCast.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZBS_2147944150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZBS!MTB"
        threat_id = "2147944150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 02 11 21 11 29 6f ?? 00 00 0a 13 2b 11 0a 12 2b 28 ?? 00 00 0a 58 13 0a 11 0b 12 2b 28 ?? 00 00 0a 58 13 0b 11 0c 12 2b 28 ?? 00 00 0a 58 13 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_PGT_2147944169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.PGT!MTB"
        threat_id = "2147944169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 16 11 17 6f ?? 00 00 0a 13 18 11 0a 12 18 28 ?? 00 00 0a 58 13 0a 11 0b 12 18 28 ?? 00 00 0a 58 13 0b 11 0c 12 18 28 ?? 00 00 0a 58 13 0c 12 18 28 ?? 00 00 0a 12 18 28 ?? 00 00 0a 58 12 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MCE_2147944293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MCE!MTB"
        threat_id = "2147944293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65}  //weight: 2, accuracy: High
        $x_1_2 = {42 00 36 00 36 00 35 00 34 00 36 00 41 00 00 0d 37 00 36 00 37 00 32 00 36 00 42}  //weight: 1, accuracy: High
        $x_1_3 = "StormCast" wide //weight: 1
        $x_1_4 = "CreateInstance" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ST_2147944752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ST!MTB"
        threat_id = "2147944752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 72 c5 05 00 70 a2 25 17 12 45 28 2b 00 00 0a a2 25 18 72 00 0a 00 70 a2 25 19 12 31 28 2b 00 00 0a a2 25 1a 72 00 0a 00 70 a2 25 1b 12 34 28 2b 00 00 0a a2 28 35 00 00 0a 13 0a 11 45 17 58 13 45 11 45 11 41 32 9c}  //weight: 2, accuracy: High
        $x_2_2 = "BackEndLibrary.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ETL_2147944803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ETL!MTB"
        threat_id = "2147944803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 76 00 00 06 0a 06 03 7d 4f 00 00 04 06 fe 06 77 00 00 06 73 d4 00 00 0a 0c 02 08 6f d5 00 00 0a 17 73 d6 00 00 0a 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZTS_2147945159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZTS!MTB"
        threat_id = "2147945159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 46 11 47 6f ?? 00 00 0a 13 48 00 2b 09 00 28 ?? 00 00 0a 13 48 00 12 48 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 56 11 56 2c 09 72 79 06 00 70 13 23 2b 41 12 48 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 57 11 57 2c 09 72 9d 06 00 70 13 23 2b 24 12 48 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 58 11 58 2c 09 72 c5 06 00 70 13 23}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZWS_2147945299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZWS!MTB"
        threat_id = "2147945299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 11 1e 11 1f 6f ?? 00 00 0a 13 21 11 08 6f ?? 00 00 0a 1f 64 fe 04 16 fe 01 13 33 11 33 2c 0a 00 11 08}  //weight: 6, accuracy: Low
        $x_5_2 = {15 5f 16 61 d2 13 26 11 24 16 60 d2 13 27 11 25 16 61 16 61 d2 13 28 11 1e 19 5a 13 29 11 1e 19 5a 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZGV_2147946133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZGV!MTB"
        threat_id = "2147946133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 02 09 11 04 6f ?? 00 00 06 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 28 ?? 00 00 06 13 07 11 07 2c 0d 00 03 11 05 28 ?? 00 00 06 00 00 2b 18 11 06 16 fe 02 13 08 11 08 2c 0d 00 03 11 05 11 06 28 ?? 00 00 06 00 00 00 11 04 17 58 13 04 11 04 08 17 94 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 09 11 09 2d 96 07 07 61 0b 00 09 17 58 0d 09 08 16 94 2f 0b 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_MCF_2147946227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MCF!MTB"
        threat_id = "2147946227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 2c 91 7e ?? 00 00 04 20 ?? 01 00 00 91 61 1f 1c 5f 9c 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EHJW_2147946273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EHJW!MTB"
        threat_id = "2147946273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 07 17 58 0b 11 16 1f 0a 5d 2d 1c 11 09 11 16 1f 64 5d 17 9c 11 08 11 16 11 08 8e 69 5d 11 16 ?? ?? ?? ?? ?? 5d d2 9c 11 16 6c 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_2147947156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.MTE!MTB"
        threat_id = "2147947156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Buttrey Food & Drug" ascii //weight: 1
        $x_1_2 = "Montero.dll" ascii //weight: 1
        $x_1_3 = "Peugeot 206" ascii //weight: 1
        $x_1_4 = "File Clerker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_APT_2147947739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.APT!MTB"
        threat_id = "2147947739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PharmaCare Manager.dll" ascii //weight: 1
        $x_1_2 = "HIPAA-compliant pharmacy management" ascii //weight: 1
        $x_1_3 = "MedTech Solutions Inc" ascii //weight: 1
        $x_1_4 = "regulated healthcare environments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AFBB_2147947868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AFBB!MTB"
        threat_id = "2147947868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 11 11 10 61 20 ff 00 00 00 5f 13 14 09 ?? ?? 00 00 01 11 11 11 10 11 12 20 ff 00 00 00 5f 11 13 20 ff 00 00 00 5f 11 14}  //weight: 5, accuracy: Low
        $x_2_2 = {11 10 1f 13 5a 11 11 1f 17 5a 58 11 04 ?? ?? 00 00 01 20 00 01 00 00 20}  //weight: 2, accuracy: Low
        $x_2_3 = {11 11 1f 11 5a 11 10 1f 1f 5a 58 11 04 ?? ?? 00 00 01 20 00 01 00 00 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZVQ_2147948393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZVQ!MTB"
        threat_id = "2147948393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 06 07 6f ?? 00 00 0a 0d 04 03 6f ?? 00 00 0a 59 13 04 72 0d 07 00 70 0e 05 8c ?? 00 00 01 28 ?? 00 00 0a 13 05 11 05 72 ?? 07 00 70 6f ?? 00 00 0a 13 0a 11 0a 2c 07}  //weight: 6, accuracy: Low
        $x_5_2 = {08 1f 63 58 0c 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 59 25 13 04 16 fe 02 16 fe 01 13 0b 11 0b 2c 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ARCB_2147949344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ARCB!MTB"
        threat_id = "2147949344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {12 00 06 7b ?? 00 00 04 08 11 07 28 ?? ?? 00 06 61 09 5a 0e 06 23 00 00 00 00 00 40 8f 40 5a 23 00 00 00 00 00 00 f0 3f 58 69 58 7d}  //weight: 5, accuracy: Low
        $x_2_2 = {03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 11 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AFDB_2147949708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AFDB!MTB"
        threat_id = "2147949708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 19 62 0e 04 11 07 28 ?? 00 00 06 11 07 1f 11 5a 58 61 0a 07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b}  //weight: 5, accuracy: Low
        $x_2_2 = {07 11 06 1f 1f 5a 06 1d 5f 58 61 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EBIU_2147949725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EBIU!MTB"
        threat_id = "2147949725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 17 13 05 2b be 16 0a 18 13 05 2b b7 04 03 61 1f 4d 59 06 61 45 01 00 00 00 06 00 00 00 1f 0b 13 05 2b a0 1b 2b f9 14 0b 11 06 1f 15 93 ?? ?? ?? ?? ?? 59 13 05 2b 8c 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EBIZ_2147949727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EBIZ!MTB"
        threat_id = "2147949727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5b 13 2b 11 2a 11 2b 5a 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 5a 13 2c 0e 05 2c 08 11 06 8e 16 fe 03 2b 01 16 13 3d 11 3d 2c 34 00 11 0d 11 1d 58 11 06 8e 69 5d 13 3e 11 06 11 3e 91 12 1e ?? ?? ?? ?? ?? 61 d2 13 3f 11 3f 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZSP_2147949947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZSP!MTB"
        threat_id = "2147949947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {5f 91 13 0f 02 11 0d 11 0e 6f ?? 00 00 0a 13 10 04 03 6f ?? 00 00 0a 59 13 11 11 11 13 12 11 12 19 fe 02 13 13 11 13 2c 03}  //weight: 6, accuracy: Low
        $x_4_2 = {16 fe 02 13 15 11 15 2c 0e 03 12 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 12 17 fe 02 13 16 11 16 2c 0e 03 12 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 12 18}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ELHD_2147951132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ELHD!MTB"
        threat_id = "2147951132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 8f 0e 00 00 01 25 71 0e 00 00 01 07 09 07 8e 69 5d 91 61 d2 81 0e 00 00 01 09 17 58 0d 09 08 8e 69 32 db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZIO_2147951381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZIO!MTB"
        threat_id = "2147951381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 17 62 11 13 61 11 04 1b 63 61 13 04 02 11 12 11 13 6f ?? 00 00 0a 13 14 04 03 6f ?? 00 00 0a 59 13 15 11 15 13 16 1a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZQO_2147951952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZQO!MTB"
        threat_id = "2147951952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 0c 11 14 1f 11 5a 58 13 15 02 11 13 11 14 6f ?? 00 00 0a 13 16 04 03 6f ?? 00 00 0a 59 13 17 11 17 13 18 11 18 19}  //weight: 6, accuracy: Low
        $x_4_2 = {11 1d 16 12 16 28 ?? 00 00 0a 9c 11 1d 17 12 16 28 ?? 00 00 0a 9c 11 1d 18 12 16 28 ?? 00 00 0a 9c 11 18 16 31 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZGN_2147952500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZGN!MTB"
        threat_id = "2147952500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 06 11 0f 1f 61 5a 61 13 10 02 11 0e 11 0f 6f ?? 00 00 0a 13 11 04 03 6f ?? 00 00 0a 59 13 12 11 12 13 13}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EFBU_2147952596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EFBU!MTB"
        threat_id = "2147952596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 0c 11 0d 17 58 1d 5a 07 11 0b 11 0d 58 07 8e 69 5d 94 61 58 13 0c}  //weight: 2, accuracy: High
        $x_2_2 = {08 17 58 07 8e 69 5d 0c 09 07 08 94 11 07 1b 5d 1f 1f 5f 62 61 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAOI_2147952598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAOI!MTB"
        threat_id = "2147952598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 1f 1d 5a 58 06 11 07 06 8e 69 5d 99 ?? ?? ?? ?? ?? ?? ?? 8f 40 5a 69 61 13 08 07 08 07 08 94 11 08 61 0e 05 1f 0f 5f 58 9e 11 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAII_2147952602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAII!MTB"
        threat_id = "2147952602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 0b 17 58 1f 25 5a 11 0e 17 58 1f 65 5a 61 07 61 13 0f 11 0f 11 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 69 61 13 0f 02 11 0b 11 0e ?? ?? ?? ?? ?? 13 10 04 03 ?? ?? ?? ?? ?? 59 13 11 11 11 13 12 11 12 19}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAOJ_2147952603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAOJ!MTB"
        threat_id = "2147952603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 0c 11 1e 1f 11 5a 58 13 1f 00 02 11 1d 11 1e ?? ?? ?? ?? ?? 13 20 04 03 ?? ?? ?? ?? ?? 59 13 21 11 21 13 22 11 22 19 fe 02 13 28 11 28 2c 03 19 13 22 11 22 16 fe 04 13 29 11 29 2c 03 16 13 22 11 0c 16 5f 13 23}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EHLJ_2147952630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EHLJ!MTB"
        threat_id = "2147952630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0c 11 0d 17 58 1d 5a 07 11 0b 11 0d 58 07 8e 69 5d 94 61 58 13 0c 02 11 0b 11 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZKN_2147952672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZKN!MTB"
        threat_id = "2147952672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {58 19 5d 13 1e 19 8d ?? 00 00 01 13 1f 11 1f 16 12 18 28 ?? 00 00 0a 9c 11 1f 17 12 18 28 ?? 00 00 0a 9c 11 1f 18 12 18 28 ?? 00 00 0a 9c 11 1a 16 fe 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AAGB_2147953320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AAGB!MTB"
        threat_id = "2147953320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1f 1e 6a 0d 0e 05 6a 08 61 09 5b 13 04 11 04}  //weight: 5, accuracy: High
        $x_2_2 = {11 0e 8e 69 17 58 11 0f 8e 69 58 17 58 06 8e 69 58 8d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AOGB_2147953756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AOGB!MTB"
        threat_id = "2147953756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 02 7d ?? 00 00 04 00 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 04 28 ?? 00 00 2b 0b 03 07 6f ?? 00 00 0a 00 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZDM_2147954055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZDM!MTB"
        threat_id = "2147954055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 11 0b 1a 63 61 61 13 0b 16 13 17 38 ?? 00 00 00 02 11 16 11 17 6f ?? 00 00 0a 13 18 04 03 6f ?? 00 00 0a 59 13 19 11 19 19 31 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EAHZ_2147954207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EAHZ!MTB"
        threat_id = "2147954207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 11 0f 11 10 ?? ?? ?? ?? ?? 13 11 04 03 ?? ?? ?? ?? ?? 59 13 12 11 12 19 31 03 19 13 12 11 12 16 2f 03 16 13 12 11 0a 16 5f 13 13 11 13 19 5d}  //weight: 2, accuracy: Low
        $x_2_2 = {58 19 5d 13 15 18 11 13 58 19 5d 13 16 19 8d 6c 00 00 01 13 17 11 17 16 12 11 ?? ?? ?? ?? ?? 9c 11 17 17 12 11 ?? ?? ?? ?? ?? 9c 11 17 18 12 11 ?? ?? ?? ?? ?? 9c 11 12}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZHM_2147954328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZHM!MTB"
        threat_id = "2147954328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 11 0e 1a 63 61 61 13 0e 16 13 2c 38 ?? 00 00 00 02 11 2b 11 2c 6f ?? 00 00 0a 13 2d 04 03 6f ?? 00 00 0a 59 13 2e 11 2e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZJM_2147954524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZJM!MTB"
        threat_id = "2147954524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0e 11 2b 20 95 00 00 00 5a 11 0e 1a 63 61 61 13 0e 16 13 2c 38 ?? 00 00 00 03 6f ?? 00 00 0a 04 3c ?? 00 00 00 02 11 2b 11 2c 6f ?? 00 00 0a 13 2d 04 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZSM_2147954913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZSM!MTB"
        threat_id = "2147954913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0b 11 46 1f 4f 5a 61 13 47 00 02 11 45 11 46 6f ?? 00 00 0a 13 48 04 03 6f ?? 00 00 0a 59 13 49 11 49 13 4a 11 4a 19 fe 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZTM_2147955028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZTM!MTB"
        threat_id = "2147955028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 11 07 1b 63 61 61 13 07 16 13 18 38 ad 00 00 00 02 11 17 11 18 6f ?? 00 00 0a 13 19 04 03 6f ?? 00 00 0a 59 13 1a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AZHB_2147955139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AZHB!MTB"
        threat_id = "2147955139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5a 61 0a 02 7b ?? 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 03 6f ?? 00 00 0a 0b 02 7b ?? 00 00 04 7b ?? 00 00 04 16 5f 0c 19 8d ?? 00 00 01 0d 09 16 12 01 28 ?? 00 00 0a 9c 09 17 12 01 28 ?? 00 00 0a 9c 09 18 12 01 28 ?? 00 00 0a 9c 19 8d ?? 00 00 01 25 16 09 08 19 5d 91 9c 25 17 09 17 08 58 19 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_EALD_2147955383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.EALD!MTB"
        threat_id = "2147955383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 16 5f 13 1b 11 1b 19 5d 13 1c 17 11 1b 58 19 5d 13 1d 18 11 1b 58 19 5d 13 1e 19}  //weight: 2, accuracy: High
        $x_2_2 = {11 10 11 0e 8e 69 17 58 11 0f 8e 69 58 1f 7c 9c 06 16 11 10 11 0e 8e 69 17 58 11 0f 8e 69 58 17 58 06 8e 69}  //weight: 2, accuracy: High
        $x_2_3 = {13 0f 11 0e 8e 69 17 58 11 0f 8e 69 58 17 58 06 8e 69 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZKL_2147956308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZKL!MTB"
        threat_id = "2147956308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 17 58 5d 58 13 0f 11 0e 17 58 6c 0e 05 5a 28 ?? 00 00 06 23 00 00 00 00 00 88 c3 40 5a 28 ?? 00 00 06 69 11 0e 20 83 00 00 00 5a 61 13 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ABKB_2147956950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ABKB!MTB"
        threat_id = "2147956950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0a 11 13 20 83 00 00 00 5a 11 14 58 61 16 5f 13 29 11}  //weight: 5, accuracy: High
        $x_2_2 = {11 09 16 28 ?? 00 00 06 02 28 ?? 00 00 06 61 02 28 ?? 00 00 06 18 62 61 13 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZGK_2147957139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZGK!MTB"
        threat_id = "2147957139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 10 2c 05 38 ?? 01 00 00 02 08 09 6f ?? 00 00 0a 13 09 03 07 6f ?? 00 00 0a 59 13 0a 11 05 07 6f ?? 00 00 0a 61 19 5f 13 12}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AOMB_2147958685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AOMB!MTB"
        threat_id = "2147958685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 05 11 06 6f ?? 00 00 0a 13 08 03 11 04 6f ?? 00 00 0a 59 13 09 11 04 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 13 11 13 2c 05 38 ?? ?? 00 00 11 04 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 14 11 14 2c 05 38 ?? ?? 00 00 11 04 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 12 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_ZXJ_2147958990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.ZXJ!MTB"
        threat_id = "2147958990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 04 11 05 6f ?? 01 00 0a 13 08 06 7b ?? 00 00 04 09 6f ?? 01 00 0a 59 13 09 09 12 08 28 ?? 01 00 0a 6f ?? 01 00 0a 11 09 17 59 25 13 09 16}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AVMB_2147959023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AVMB!MTB"
        threat_id = "2147959023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 04 11 05 6f ?? 00 00 0a 13 08 06 7b ?? 00 00 04 09 6f ?? 00 00 0a 59 13 09 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 12 11 12 2c 05 38 ?? 00 00 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 13 11 13 2c 05 38 ?? 00 00 00 09 12 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Taskun_AINB_2147959513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Taskun.AINB!MTB"
        threat_id = "2147959513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 09 6f ?? 00 00 0a 13 05 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 17 13 04 2b 35 11 04 17 fe 01 13 0e 11 0e 2c 14 00 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 18 13 04 2b 16 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 58 0d 16 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

