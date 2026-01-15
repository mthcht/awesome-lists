rule Trojan_MSIL_Tasker_NEAB_2147834398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.NEAB!MTB"
        threat_id = "2147834398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 30 00 00 0a 0a 06 72 64 01 00 70 6f 31 00 00 0a 06 72 74 01 00 70 28 0d 00 00 06 28 13 00 00 06 28 10 00 00 0a 6f 32 00 00 0a 06 17 6f 33 00 00 0a 06 16 6f 34 00 00 0a 06 28 35 00 00 0a 26 2a}  //weight: 10, accuracy: High
        $x_5_2 = "clipper.guru" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_AUUG_2147836989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.AUUG!MTB"
        threat_id = "2147836989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 1a 8d ?? ?? ?? 01 0b 03 15 16 6f ?? ?? ?? 0a 26 03 07 16 1a 16 6f ?? ?? ?? 0a 0c 07 16 28 ?? ?? ?? 0a 0d 09 13 04 09 8d ?? ?? ?? 01 13 05 2b 17 03 11 05 06 11 04 16 6f ?? ?? ?? 0a 0c 06 08 58 0a 11 04 08 59 13 04 06 09 32 e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_NEAC_2147838072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.NEAC!MTB"
        threat_id = "2147838072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 14 0b 06 8e 69 1a 58 7e 01 00 00 04 8e 69 30 36 16 0d 2b 19 06 09 8f 0e 00 00 01 25 47 7e 01 00 00 04 09 1a 58 91 5a d2 52 09 17 58 0d 09 06 8e 69 32 e1 06 28 1a 00 00 0a 0c 28 1b 00 00 0a}  //weight: 10, accuracy: High
        $x_2_2 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_PSIR_2147844984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.PSIR!MTB"
        threat_id = "2147844984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 7e f8 01 00 04 7e f7 01 00 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 73 ?? ?? ?? 0a 0b 07 72 69 16 00 70 6f ?? ?? ?? 0a 00 07 17 6f ?? ?? ?? 0a 00 07 1b 8d 4c 00 00 01 25 16 72 83 16 00 70 a2 25 17 7e f7 01 00 04 28 ?? ?? ?? 0a a2 25 18 72 c7 16 00 70 a2 25 19 7e f8 01 00 04 a2 25 1a 72 d7 16 00 70 a2 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 28 ?? ?? ?? 0a 0c 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_MBDT_2147845444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.MBDT!MTB"
        threat_id = "2147845444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 73 01 00 70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 09 6f ?? 00 00 0a a2 28 ?? 00 00 0a 74 ?? 00 00 01 13 04 11 04 6f ?? 00 00 0a 16 9a 7e ?? 00 00 04 13 0a 11 0a 28}  //weight: 1, accuracy: Low
        $x_1_2 = "BusinessSimulation.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_GKH_2147850653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.GKH!MTB"
        threat_id = "2147850653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fe 0c 08 00 fe 0c 0a 00 8f 14 00 00 01 25 71 14 00 00 01 fe 0c 02 00 d2 61 d2 81 14 00 00 01 fe 0c 0a 00 20 ff 00 00 00 5f 3a 14 00 00 00 fe 0c 02 00 fe 0c 02 00 5a 20 b7 5c 8a 00 6a 5e fe 0e 02 00 fe 0c 0a 00 20 01 00 00 00 58 fe 0e 0a 00 fe 0c 0a 00 fe 0c 08 00 8e 69}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_AMAA_2147896270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.AMAA!MTB"
        threat_id = "2147896270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 08 6f ?? ?? 00 0a 1f 20 08 6f ?? ?? 00 0a 8e 69 1f 20 59 6f ?? ?? 00 0a 0a 1f 20 8d ?? ?? ?? 01 0b 08 07 16 07 8e 69 6f ?? ?? ?? 0a 26 02 06 07 0a 0b 26 17 13 07 16}  //weight: 5, accuracy: Low
        $x_5_2 = {0a 08 25 06 16 1f 10 6f ?? 00 00 0a 26 09 25 06 6f ?? 00 00 0a 6f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_GBX_2147896362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.GBX!MTB"
        threat_id = "2147896362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {59 65 20 2d 22 19 e9 58 20 01 00 00 00 63 20 ?? ?? ?? 0b 58 61 fe 09 00 00 61 d1 9d fe 0c 01 00 20 ?? ?? ?? 21 65 20 ?? ?? ?? de 59 59 25 fe 0e 01 00 20 ?? ?? ?? 22 20 ?? ?? ?? ed 59 20 ?? ?? ?? 19 59 20 ?? ?? ?? 14 59 66 20 ?? ?? ?? 07 61 20 ?? ?? ?? ff 59 20 ?? ?? ?? 00 63}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_ILAA_2147905677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.ILAA!MTB"
        threat_id = "2147905677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 ?? 08 20 0e 02 00 00 58 20 0d 02 00 00 59 1b 59 1b 58 ?? 8e 69 5d 1f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_NB_2147919498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.NB!MTB"
        threat_id = "2147919498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 06 11 04 06 11 04 91 ?? ?? ?? 00 00 59 d2 9c 00 11 04 17 58 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "https://onedrive.live.com/download?resid=59261C7E41B6478A%21223&authkey=!AEJZW7GtRXEfOGc" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "System.Reflection.Assembly" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tasker_PGDK_2147961176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tasker.PGDK!MTB"
        threat_id = "2147961176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "C:\\Users\\Public\\Downloads\\Securit.exe" ascii //weight: 5
        $x_5_2 = {72 00 75 00 6e 00 61 00 73 00 [0-2] 53 00 79 00 73 00 74 00 65 00 6d 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 54 00 61 00 73 00 6b 00 [0-2] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 74 00 6e 00 20 00 22 00 [0-2] 22 00 20 00 2f 00 74 00 72 00 20 00 22 00 5c 00 22 00 [0-2] 5c 00 22 00 22 00 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 20 00 2f 00 64 00 65 00 6c 00 61 00 79 00 20 00 30 00 30 00 30 00 30 00 3a 00 33 00 30 00 20 00 2f 00 72 00 6c 00 20 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 [0-2] 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00}  //weight: 5, accuracy: Low
        $x_5_3 = {72 75 6e 61 73 [0-2] 53 79 73 74 65 6d 55 70 64 61 74 65 72 54 61 73 6b [0-2] 2f 63 72 65 61 74 65 20 2f 66 20 2f 74 6e 20 22 [0-2] 22 20 2f 74 72 20 22 5c 22 [0-2] 5c 22 22 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 64 65 6c 61 79 20 30 30 30 30 3a 33 30 20 2f 72 6c 20 68 69 67 68 65 73 74 [0-2] 73 63 68 74 61 73 6b 73}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

