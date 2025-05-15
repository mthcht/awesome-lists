rule Trojan_MSIL_Fsysna_AVSS_2147836103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AVSS!MTB"
        threat_id = "2147836103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 08 6f ?? ?? ?? 0a 9c 00 09 17 d6 0d 09 6a 06 6f ?? ?? ?? 0a fe 04 13 08 11 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AAXQ_2147836104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AAXQ!MTB"
        threat_id = "2147836104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 16 13 04 2b 3b 09 11 04 9a 0a 00 00 06 19 18 73 1a 00 00 0a 0b 07 73 1b 00 00 0a 0c 08 02 7b 01 00 00 04 6f}  //weight: 2, accuracy: High
        $x_1_2 = "Dragtor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_GBX_2147837774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.GBX!MTB"
        threat_id = "2147837774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 8d 39 00 00 01 13 04 7e a5 00 00 04 02 1a 58 11 04 16 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 7e 8f 00 00 04 11 05 6f ?? ?? ?? 0a 7e}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_NS_2147839772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.NS!MTB"
        threat_id = "2147839772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64CharArray" ascii //weight: 1
        $x_1_2 = "TGG7u1N4Q9Yf08NF" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "tsr1St0Y57xYVu28" ascii //weight: 1
        $x_1_6 = "Roblox.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_NF_2147845663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.NF!MTB"
        threat_id = "2147845663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 47 00 00 0a 74 ?? ?? ?? 01 13 03 38 ?? ?? ?? 00 dd ?? ?? ?? ff 38 ?? ?? ?? ff 11 00 11 01 16 11 01 8e 69 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Tvcxnxuudjtlmryajdiuur.Properties.Resources" ascii //weight: 1
        $x_1_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_NLF_2147845770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.NLF!MTB"
        threat_id = "2147845770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 31 00 00 0a 80 ?? ?? ?? 04 20 ?? ?? ?? 00 38 ?? ?? ?? ff 20 ?? ?? ?? 06 20 ?? ?? ?? 86 58 20 ?? ?? ?? fb 61 7e ?? ?? ?? 04 7b ?? ?? ?? 04 61 7e ?? ?? ?? 04 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "dlexec" wide //weight: 1
        $x_1_3 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_PSLB_2147846129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.PSLB!MTB"
        threat_id = "2147846129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 6e 00 00 0a fe 0c 00 00 20 02 00 00 00 9a 28 ?? ?? ?? 0a 25 fe 0c 00 00 20 01 00 00 00 9a 28 70 00 00 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 20 b8 94 a4 51 38 cb fd ff ff fe 0c 04 00 20 32 f6 2b 35 5a 20 45 29 60 68 61 38 b6 fd ff ff fe 0c 01 00 72 b5 06 00 70 28 58 00 00 06 20 20 00 00 00 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AAGU_2147851428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AAGU!MTB"
        threat_id = "2147851428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 72 a3 03 00 70 28 ?? 00 00 06 26 06 72 ad 03 00 70 28 ?? 00 00 06 26 06 72 bd 03 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b 2b 00 07 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AAHD_2147851570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AAHD!MTB"
        threat_id = "2147851570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 1d 0b 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 02 28 ?? 00 00 06 0c 2b 00 08 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "8+illVLu1ci9ZAaUwOoVFZr/Zhg0D9BU8tuEGGy0JLY=" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AAHJ_2147851642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AAHJ!MTB"
        threat_id = "2147851642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0b 08 16 8c ?? 00 00 01 07 6f ?? 00 00 0a 17 da 8c ?? 00 00 01 17 8c ?? 00 00 01 12 03 12 02 28 ?? 00 00 0a 39 ?? 00 00 00 06 07 08 28 ?? 00 00 0a 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 08 09 12 02 28 ?? 00 00 0a 2d d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_GP_2147853231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.GP!MTB"
        threat_id = "2147853231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 3a 00 2f 00 55 00 73 00 65 00 72 00 73 00 2f 00 50 00 75 00 62 00 6c 00 69 00 63 00 2f 00 4d 00 75 00 73 00 69 00 63 00 2f 00 64 00 6c 00 6c 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 3a 00 2f 00 55 00 73 00 65 00 72 00 73 00 2f 00 50 00 75 00 62 00 6c 00 69 00 63 00 2f 00 4d 00 75 00 73 00 69 00 63 00 2f 00 18 52 2a 82 3a 8d 2d 00 80 7b 86 53 2e 00 64 00 6f 00 63 00 78}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 31 00 35 00 2e 00 31 00 35 00 39 00 2e 00 31 00 30 00 32 00 2e 00 31 00 31 00 32 00 3a 00 38 00 30 00 38 00 30 00 2f 00 64 00 6c 00 6c 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 31 00 35 00 2e 00 31 00 35 00 39 00 2e 00 31 00 30 00 32 00 2e 00 31 00 31 00 32 00 3a 00 38 00 30 00 38 00 30 00 2f 00 18 52 2a 82 3a 8d 2d 00 80 7b 86 53 2e 00 64 00 6f 00 63 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AARR_2147892482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AARR!MTB"
        threat_id = "2147892482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 37 01 00 70 6f ?? 00 00 0a 0a 06 73 ?? 00 00 06 0b 07 03 6f ?? 00 00 06 0c 07 73 ?? 00 00 06 0d 09 6f ?? 00 00 06 00 08 13 04 2b 00 11 04 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "EGA+uSQ0MjAp0kgyjMDq1Sh06T381wPFpmPneiNF8KM=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AFS_2147892651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AFS!MTB"
        threat_id = "2147892651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 13 00 00 0a 0a 73 14 00 00 0a 0b 07 72 1f 00 00 70 6f ?? 00 00 0a 0a de 0a 07 2c 06 07 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AFS_2147892651_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AFS!MTB"
        threat_id = "2147892651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 06 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 2b 1e 00 08 11 06 16 11 07 6f 22 00 00 0a 00 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 00 11 07 16 fe 02 13 09 11 09 2d d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AFS_2147892651_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AFS!MTB"
        threat_id = "2147892651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 2b 4d 12 01 28 ?? 00 00 0a 0c 08 73 21 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 09 28}  //weight: 2, accuracy: Low
        $x_1_2 = "twobit69 or lifeofacookie" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_PTGY_2147905355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.PTGY!MTB"
        threat_id = "2147905355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 01 00 0a 28 ?? 02 00 06 04 6f 01 01 00 0a 28 ?? 02 00 06 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_IOAA_2147905776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.IOAA!MTB"
        threat_id = "2147905776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 11 0a 6f ?? 00 00 0a 25 11 09 6f ?? 00 00 0a 6f ?? 00 00 0a 11 08 16 11 08 8e 69 6f ?? 00 00 0a 13 08}  //weight: 5, accuracy: Low
        $x_1_2 = "Payaret" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_KAA_2147907241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.KAA!MTB"
        threat_id = "2147907241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 06 07 93 19 5b d1 9d 07 17 58 0b 07 06 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_SID_2147927536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.SID!MTB"
        threat_id = "2147927536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 99 00 00 04 02 7b 9b 00 00 04 02 7b ac 00 00 04 6f 57 00 00 06 28 cc 00 00 0a 06 17 28 cd 00 00 0a 72 82 39 00 70 28 20 00 00 06 72 ab 38 00 70 28 20 00 00 06 28 ce 00 00 0a 72 82 39 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fsysna_AYA_2147941499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fsysna.AYA!MTB"
        threat_id = "2147941499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mrlogonui.ru" wide //weight: 2
        $x_1_2 = "svchost.Form1.resources" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" wide //weight: 1
        $x_1_4 = "DisableAntiVirus" wide //weight: 1
        $x_1_5 = "DisableRealtimeMonitoring" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

