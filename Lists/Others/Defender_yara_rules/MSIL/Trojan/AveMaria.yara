rule Trojan_MSIL_AveMaria_N_2147823619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.N!MTB"
        threat_id = "2147823619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 00 00 00 01 00 00 00 01 00 00 00 05 00 00 00 0e 00 00 00 01 00 00 00 01 00 00 00 08 00 00 00 19 00 00 00 32 00 00 00 02 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 f5 b6 3d 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 64 00 00 00 1e 00 00 00 3b 00 00 00 93 00 00 00 99 00 00 00 8a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RPV_2147823851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RPV!MTB"
        threat_id = "2147823851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "maidanze.000webhostapp.com" wide //weight: 1
        $x_1_2 = "BASE64.txt" wide //weight: 1
        $x_1_3 = "RRUUNNN" wide //weight: 1
        $x_1_4 = "newddll.txt" wide //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NE_2147825085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NE!MTB"
        threat_id = "2147825085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 72 00 00 0a 6f ?? 00 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "tree checker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NE_2147825085_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NE!MTB"
        threat_id = "2147825085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 01 00 00 70 28 ?? ?? ?? 06 0a 06 73 ?? ?? ?? 0a 0b 00 73 04 00 00 0a 0c 00 07 16 73 05 00 00 0a 73 06 00 00 0a 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "ramankumarynr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEA_2147825086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEA!MTB"
        threat_id = "2147825086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 0d 00 00 04 11 04 7e ?? ?? ?? 04 11 04 91 20 ?? ?? ?? 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 8e 69 fe 04}  //weight: 5, accuracy: Low
        $x_1_2 = "IQnuin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEA_2147825086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEA!MTB"
        threat_id = "2147825086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 09 8f 65 00 00 01 72 94 0a 00 70 28 6b 00 00 0a 6f 6c 00 00 0a 26 00 09 17 58 0d 09 07 8e 69 fe 04 13 04 11 04 2d d6}  //weight: 1, accuracy: High
        $x_1_2 = "5XTOD5G4Q54GZ857BSC874" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEA_2147825086_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEA!MTB"
        threat_id = "2147825086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 ca 01 00 06 00 11 08 20 ?? ?? ?? 75 5a 20 ?? ?? ?? 73 61 38 ?? ?? ?? ff 00 11 08 20 ?? ?? ?? b3 5a 20 ?? ?? ?? 6a 61 38 ?? ?? ?? ff 02 28 ?? ?? ?? 06 09 28 ?? ?? ?? 06 00 11 08 20 ?? ?? ?? 59 5a 20 ?? ?? ?? 87 61 38 ?? ?? ?? ff 11 05 28 ?? ?? ?? 06 20 ?? ?? ?? 8a 28 ?? ?? ?? 2b}  //weight: 5, accuracy: Low
        $x_1_2 = "MaTacGia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEB_2147825935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEB!MTB"
        threat_id = "2147825935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 02 11 04 02 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 11 04 91 28 ?? ?? ?? 06 9c 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 8e 69 fe 04 13 05 11 05 2d c5}  //weight: 1, accuracy: Low
        $x_1_2 = "Q10VBII8JDS5HCB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEC_2147825939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEC!MTB"
        threat_id = "2147825939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 25 17 58 10 00 91 1f 18 62 60 0c 28 31 00 00 0a 7e 01 00 00 04 02 08 6f 32 00 00 0a 28 33 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "Gomoku" ascii //weight: 1
        $x_1_3 = "TaskTo.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_ABS_2147827745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.ABS!MTB"
        threat_id = "2147827745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 06 91 20 ?? ?? ?? 00 59 d2 9c 00 06 17 58 0a 06 7e 03 ?? ?? 04 8e 69 fe 04 0b 07 2d d7 7e 03 ?? ?? 04 0c 2b 00 08 2a 32 00 7e 03 ?? ?? 04 06 7e 03}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "DownloadData" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_ABS_2147827745_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.ABS!MTB"
        threat_id = "2147827745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 17 26 7e 57 ?? ?? 04 fe 06 ?? ?? ?? 06 73 4f ?? ?? 0a 25 80 58 ?? ?? 04 28 04 ?? ?? 2b 28 05 ?? ?? 2b 02 fe 06 ?? ?? ?? 06 73 52 ?? ?? 0a 28 06 ?? ?? 2b 28 07 ?? ?? 2b 0a 20 87 ?? ?? 4e 2b 8d 07 20 86 ?? ?? 2d 5a 20 82 ?? ?? 70 61 38 7b ?? ?? ff 64 00 02 7b 52 ?? ?? 04 6f 4e ?? ?? 0a 7e 58 ?? 00 04 25}  //weight: 2, accuracy: Low
        $x_2_2 = {11 04 20 05 ?? ?? 53 5a 20 cf ?? ?? 12 61 2b c6 18 00 28 9c ?? ?? 06 0a 16 0b}  //weight: 2, accuracy: Low
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NED_2147828117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NED!MTB"
        threat_id = "2147828117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CMCeCtChCoCdC0CCCCCCCCC" wide //weight: 1
        $x_1_2 = "SdVbcskldfjp" wide //weight: 1
        $x_1_3 = "Petugas" wide //weight: 1
        $x_1_4 = "Pemberitahuan" wide //weight: 1
        $x_1_5 = "kode_pinjam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEE_2147828312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEE!MTB"
        threat_id = "2147828312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$9ff822ce-8783-422b-8f4a-4738b3fc0feb" ascii //weight: 1
        $x_1_2 = "getfMomentomd2x" ascii //weight: 1
        $x_1_3 = "mainBeamSpec" ascii //weight: 1
        $x_1_4 = "The Flying Bear ltd 2022" ascii //weight: 1
        $x_1_5 = "failureWay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEF_2147828316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEF!MTB"
        threat_id = "2147828316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Suczdvsdsdvfcdsasdcess" ascii //weight: 1
        $x_1_2 = "FailgdfsdacsddghdshsdhBegin" ascii //weight: 1
        $x_1_3 = "ObfuscatedByGoliath" ascii //weight: 1
        $x_1_4 = "Ivan Meedev" ascii //weight: 1
        $x_1_5 = "C:\\Tefsdssddddmp" wide //weight: 1
        $x_1_6 = "C:\\NeddssssssssssssssddddddddddddddddddddwTemp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEG_2147828317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEG!MTB"
        threat_id = "2147828317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$7C18A7B3-A6D7-44A5-BD43-C892F72FB204" ascii //weight: 1
        $x_1_2 = "Reservation_agent Volkswagen" ascii //weight: 1
        $x_1_3 = "9B5BFE1F12F510D705F637723F7F9CB33CEF76747A5E4134659B8933740FD892" ascii //weight: 1
        $x_1_4 = "umLocehuEC" ascii //weight: 1
        $x_1_5 = "$$method0x6000317-1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NYY_2147828559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NYY!MTB"
        threat_id = "2147828559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QT8J9ZJF88887578VHS7HB" wide //weight: 1
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "Politic" wide //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "GetObject" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NYT_2147828708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NYT!MTB"
        threat_id = "2147828708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 04 01 00 0a 0d 09 08 6f 05 01 00 0a 09 18 6f 06 01 00 0a 09 6f 07 01 00 0a 06 16 06 8e 69 6f 08 01 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "$6be5da63-4179-4a9d-b053-b79e7c905205" ascii //weight: 1
        $x_1_3 = "Builders Emporium 2022 (C)" ascii //weight: 1
        $x_1_4 = "Kruskal.Properties.Resources.resource" ascii //weight: 1
        $x_1_5 = {17 a2 0b 09 07 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a6 00 00 00 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEH_2147828747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEH!MTB"
        threat_id = "2147828747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 13 04 2b 03 0b 2b ?? 11 04 06 8e 69 32 02 2b 05 2b cc 0a 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MB_2147829582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MB!MTB"
        threat_id = "2147829582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 08 2b 09 06 18 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b f0 20 ?? ?? ?? ?? 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 0d 2b 03 0c 2b d1 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 de 14}  //weight: 10, accuracy: Low
        $x_1_2 = "DynamicInvoke" ascii //weight: 1
        $x_1_3 = "GetCurrentProcess" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEJ_2147829896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEJ!MTB"
        threat_id = "2147829896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "get__6d87295c62f05b207f13a086fc604a17" ascii //weight: 5
        $x_5_2 = "get_b11619ca4d66ceeb59c7c5fb8e8e738d" ascii //weight: 5
        $x_2_3 = "IDATx" ascii //weight: 2
        $x_2_4 = "ceeb59c7c5fb8e8e738d" ascii //weight: 2
        $x_1_5 = "Embalmer" ascii //weight: 1
        $x_1_6 = "WordRack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEK_2147829897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEK!MTB"
        threat_id = "2147829897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 73 10 00 00 0a 28 11 00 00 0a 74 ?? 00 00 01 6f ?? 00 00 0a 74 ?? 00 00 01 73 13 00 00 0a 0a 25 6f 14 00 00 0a 06 6f 15 00 00 0a 6f 16 00 00 0a 06 6f 17 00 00 0a 06 6f 18 00 00 0a 0b dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEL_2147829898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEL!MTB"
        threat_id = "2147829898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 09 20 00 01 00 00 6f 4c 00 00 0a 00 09 08 6f 4d 00 00 0a 00 09 18 6f 4e 00 00 0a 00 09 6f 4f 00 00 0a 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEM_2147829899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEM!MTB"
        threat_id = "2147829899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 11 04 3f ?? 00 00 00 d0 ?? 00 00 01 28 07 00 00 0a 09 28 08 00 00 0a 16 8d ?? 00 00 01 6f 09 00 00 0a 26 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEO_2147830034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEO!MTB"
        threat_id = "2147830034"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s_msyR" ascii //weight: 1
        $x_1_2 = "seniorhigh_sy" wide //weight: 1
        $x_1_3 = "HdfkglTTP\\shhljhlell\\ophklklen\\cohlkhlhkmmand" wide //weight: 1
        $x_1_4 = "TTTTToTTTdTTTTTT0TTTT" wide //weight: 1
        $x_1_5 = "XCVDGDFHDUT6876II" wide //weight: 1
        $x_1_6 = "d74r3j93527" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEP_2147830091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEP!MTB"
        threat_id = "2147830091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FacifsdtrsddhhjgsgdsddsdhsdhsdlUpdate" ascii //weight: 2
        $x_2_2 = "FaildgfsdtrtrdhasdcdgfesddghdshsdhBegin" ascii //weight: 2
        $x_2_3 = "Suczdvsdsdvfctgjesgddsdrdsasdcess" ascii //weight: 2
        $x_2_4 = "ObfuscatedByGoliath" ascii //weight: 2
        $x_1_5 = "C:\\sogggggggggmedirectory" wide //weight: 1
        $x_1_6 = "C:\\NeddssssssssssssssddddddddddddddddddddwTemp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NES_2147830479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NES!MTB"
        threat_id = "2147830479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 06 6f 21 00 00 0a 0d 07 09 6f 22 00 00 0a 07 18 6f 23 00 00 0a 02 13 04 07 6f 24 00 00 0a 11 04 16 11 04 8e 69 6f 25 00 00 0a 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NET_2147830480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NET!MTB"
        threat_id = "2147830480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Yfeffeefefef" ascii //weight: 3
        $x_3_2 = "get_PeachPuff" ascii //weight: 3
        $x_3_3 = "Torty1.Properties" ascii //weight: 3
        $x_2_4 = "2System.Collections.CaseInsensitiveHashCodeProvider" ascii //weight: 2
        $x_2_5 = "Management Assistant" ascii //weight: 2
        $x_2_6 = "Complete Tech" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEU_2147830644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEU!MTB"
        threat_id = "2147830644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0f 00 00 01 6f 20 00 00 0a 74 11 00 00 01 0a 73 21 00 00 0a 0b 06 6f 22 00 00 0a 0c 20 00 10 00 00 8d 14 00 00 01 0d 38 0a 00 00 00 07 09 16 11 04 6f 23 00 00 0a 08 09}  //weight: 1, accuracy: High
        $x_1_2 = "Ardao_Rapcfzvu.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEV_2147830645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEV!MTB"
        threat_id = "2147830645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 0e 02 00 0a 0c 08 07 1f 10 6f 0f 02 00 0a 6f 10 02 00 0a 00 08 07 1f 10 6f 0f 02 00 0a 6f 11 02 00 0a 00 08 6f 12 02 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "545BGGP79TP5ND87G5XQ88" wide //weight: 1
        $x_1_3 = "Aintac" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEW_2147830646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEW!MTB"
        threat_id = "2147830646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 28 07 00 00 0a 13 06 28 08 00 00 0a 11 06 6f 09 00 00 0a 13 07 11 07 13 08 11 04 11 08 08 6f 0a 00 00 0a 07 08 19 17 73 24 1d 00 06 7d 8c 14 00 04 07}  //weight: 1, accuracy: High
        $x_1_2 = "==FlPK0duRcvlecZTg" wide //weight: 1
        $x_1_3 = "ConflictingRenderStateException.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEX_2147830851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEX!MTB"
        threat_id = "2147830851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 7e 6f 00 00 04 28 a7 00 00 0a 0a 17 72 b5 14 00 70 28 4c 00 00 06 0b 73 a8 00 00 0a 0c 08 1f 10 07 28 4b 00 00 06 74 07 00 00 1b 6f a9 00 00 0a 00 08 1f 10 07 28 4b 00 00 06 74 07 00 00 1b 6f aa 00 00 0a 00 08}  //weight: 1, accuracy: High
        $x_1_2 = "57H3FNPC54JHXFFF8DC347" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEY_2147830852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEY!MTB"
        threat_id = "2147830852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 20 00 00 0a 06 20 e8 03 00 00 73 21 00 00 0a 0d 08 09 08 6f 22 00 00 0a 1e 5b 6f 23 00 00 0a 6f 24 00 00 0a 08 09 08 6f 25 00 00 0a 1e 5b}  //weight: 1, accuracy: High
        $x_1_2 = "Texpfraslppemzbibyngx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEQ_2147830931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEQ!MTB"
        threat_id = "2147830931"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cG93ZXJzaGVsbC5leGU=" wide //weight: 1
        $x_1_2 = "Rm9ybTE=" wide //weight: 1
        $x_1_3 = "UnVudGltZUJyb2tlci5Qcm9wZXJ0aWVzLlJlc291cmNlcw==" wide //weight: 1
        $x_1_4 = "VXNlciBtb2Rl" wide //weight: 1
        $x_1_5 = "UnVudGltZUJyb2tlci5leGU=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAA_2147830932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAA!MTB"
        threat_id = "2147830932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 02 7b 36 00 00 04 07 91 06 07 91 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0c 08 2d e0}  //weight: 1, accuracy: High
        $x_1_2 = "0FE2B783CBAB" ascii //weight: 1
        $x_1_3 = "BAED64233981" ascii //weight: 1
        $x_1_4 = "/neeeYu" ascii //weight: 1
        $x_1_5 = "31.2087496,29.9091634" wide //weight: 1
        $x_1_6 = "CAN_SATDataSet1.xsd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAC_2147831123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAC!MTB"
        threat_id = "2147831123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$ea01dce7-dd7b-42d3-bfff-b8ee9f304d19" ascii //weight: 5
        $x_4_2 = "b77a5c561934e089" ascii //weight: 4
        $x_3_3 = "Isaly's 2022" ascii //weight: 3
        $x_3_4 = "Photographic Spotter" ascii //weight: 3
        $x_2_5 = "Friedman" ascii //weight: 2
        $x_2_6 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAD_2147831126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAD!MTB"
        threat_id = "2147831126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 14 14 28 32 00 00 0a 28 38 00 00 0a 72 ?? 01 00 70 28 38 00 00 0a 02 7b ?? 00 00 04 14 72 53 00 00 70 16 8d 03 00 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = "jhdafiooeyt8e9wt7w" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAE_2147831360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAE!MTB"
        threat_id = "2147831360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 28 1e 00 00 0a 72 ?? 00 00 70 6f 1f 00 00 0a 6f 20 00 00 0a 0c 06 08 6f 21 00 00 0a 06 18 6f 22 00 00 0a 72 ?? 00 00 70 28 03 00 00 06 0d 06 6f 23 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAF_2147831361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAF!MTB"
        threat_id = "2147831361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "11S11y11s11t11e11m11" wide //weight: 5
        $x_5_2 = "11R11e11f11l11e11c11t11i11o11n11" wide //weight: 5
        $x_5_3 = "11A11s11s11e11m11b11l11y11" wide //weight: 5
        $x_4_4 = "zxlxvisodjoewuut3" wide //weight: 4
        $x_4_5 = "cvhmkjyui78" wide //weight: 4
        $x_3_6 = "{0}://{1}.{2}.{3}" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAG_2147831362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAG!MTB"
        threat_id = "2147831362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f 98 00 00 0a 13 05 72 43 01 00 70 28 57 00 00 0a 13 06 28 b2 00 00 0a 11 06 6f 98 00 00 0a 13 07 28 b3 00 00 0a 6f b4 00 00 0a 13 08 08 28 b5 00 00 0a 13 09 19 8d 02 00 00 01 13 0b 11 0b 16 11 08 a2 11 0b}  //weight: 5, accuracy: High
        $x_3_2 = "UHVibGlzaGVySWRlbnRpdHlQZXJtaXNzaW9uQXR0cmlidXRlLklVbnJlc3RyaWN0ZWRQZXJtaXNzaW9u" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAH_2147831363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAH!MTB"
        threat_id = "2147831363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 2b e6 08 2b e5 6f 1f 00 00 0a 2b e0 08 2b df 6f 20 00 00 0a 2b da 07 2b d9 6f 21 00 00 0a 2b d4 08 2b d3}  //weight: 1, accuracy: High
        $x_1_2 = "teenfashionbd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAI_2147831364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAI!MTB"
        threat_id = "2147831364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LvlEditor.AAAAAAAAAAA.resources" ascii //weight: 5
        $x_4_2 = "get_SpikesBegin" ascii //weight: 4
        $x_4_3 = "get_HotelCheck_In" ascii //weight: 4
        $x_4_4 = "get_TicksPerSecond" ascii //weight: 4
        $x_4_5 = "tsmiDeleteMode_Click" ascii //weight: 4
        $x_4_6 = "get_Fuchsia" ascii //weight: 4
        $x_4_7 = "get_PowderBlue" ascii //weight: 4
        $x_4_8 = "get_BlanchedAlmond" ascii //weight: 4
        $x_4_9 = "get_Password2_" ascii //weight: 4
        $x_3_10 = "musicVOL" ascii //weight: 3
        $x_3_11 = "J%GIE" ascii //weight: 3
        $x_3_12 = "NewKulaLevel" ascii //weight: 3
        $x_3_13 = "IncomingTeleports" ascii //weight: 3
        $x_3_14 = "HangHoa_" ascii //weight: 3
        $x_3_15 = "LowerSurf" ascii //weight: 3
        $x_1_16 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_17 = "RijndaelManaged" ascii //weight: 1
        $x_1_18 = "v4.0.30319" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAJ_2147831458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAJ!MTB"
        threat_id = "2147831458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Davis11.FormBase.resources" ascii //weight: 5
        $x_5_2 = "UVmVw6" ascii //weight: 5
        $x_5_3 = "azhans" ascii //weight: 5
        $x_5_4 = "Y5tFvU8EY" wide //weight: 5
        $x_3_5 = "get_KeyCode" ascii //weight: 3
        $x_3_6 = "get_sorcecity" ascii //weight: 3
        $x_3_7 = "get_Password" ascii //weight: 3
        $x_3_8 = "get_IsleTopL" ascii //weight: 3
        $x_2_9 = "CRUDpersonels_DLL" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAK_2147831460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAK!MTB"
        threat_id = "2147831460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "aR3nbf8dQp2feLmk31" ascii //weight: 5
        $x_5_2 = "KDikMXewCI" ascii //weight: 5
        $x_3_3 = "Enrich Garden Services" ascii //weight: 3
        $x_3_4 = "ng trong kho!(" wide //weight: 3
        $x_3_5 = "DayStart" ascii //weight: 3
        $x_3_6 = "set_Checked" ascii //weight: 3
        $x_2_7 = "FindStaffBySpells" wide //weight: 2
        $x_1_8 = "LoadLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAL_2147831461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAL!MTB"
        threat_id = "2147831461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 09 07 09 07 8e 69 5d 91 02 09 91 61 d2 9c 09 17 58 0d 09 02 8e 69 32 e7}  //weight: 1, accuracy: High
        $x_1_2 = "Ujikslytoggmf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAM_2147831767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAM!MTB"
        threat_id = "2147831767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ZZRZZZeZZZfZZZlZZZeZZZcZZZtZZZiZZZoZZZnZZZ" wide //weight: 5
        $x_5_2 = "cvbchre5y" wide //weight: 5
        $x_5_3 = "poiilunbvcsferty" wide //weight: 5
        $x_5_4 = "mjhliou75dgvf" wide //weight: 5
        $x_3_5 = "{0}://{1}.{2}.{3}" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAN_2147831768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAN!MTB"
        threat_id = "2147831768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 2d 00 00 04 28 12 00 00 06 72 d0 15 00 70 72 01 00 00 70 6f 9b 00 00 0a 6f 4a 00 00 0a 00 02 7b 30 00 00 04 02 28 39 00 00 06 6f 4a 00 00 0a 00 7e 27 00 00 04 74 68 00 00 01 6f bc 00 00 0a 16 9a 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAO_2147831770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAO!MTB"
        threat_id = "2147831770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 09 11 04 28 3b 00 00 06 13 05 08 09 11 04 6f 8d 00 00 0a 13 06 11 06 28 8e 00 00 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAR_2147832165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAR!MTB"
        threat_id = "2147832165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 86 00 00 0a 28 66 00 00 0a 20 ?? ?? ?? ?? 28 0a 00 00 06 28 52 00 00 06 28 51 00 00 06 6f 87 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {6f 96 00 00 0a 1e 5b 6f 97 00 00 0a 6f 98 00 00 0a 06 11 04 06 6f 99 00 00 0a 1e 5b 6f 97 00 00 0a 6f 9a 00 00 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_ABT_2147832230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.ABT!MTB"
        threat_id = "2147832230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 07 91 20 ?? ?? ?? 00 59 d2 9c 00 07 17 58 0b 07 7e ?? ?? ?? 04 8e 69 fe 04 0c 08 2d d7 7e ?? ?? ?? 04 0d de 0b 30 00 7e ?? ?? ?? 04 07 7e 01}  //weight: 1, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "Aertop.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAS_2147832259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAS!MTB"
        threat_id = "2147832259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 02 8e 69 32 e4}  //weight: 5, accuracy: Low
        $x_4_2 = {7b 01 00 00 04 28 03 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAU_2147832376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAU!MTB"
        threat_id = "2147832376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 08 6f ?? 00 00 0a 09 20 00 01 00 00 14 14 11 06 74 02 00 00 1b 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {1a 8d 15 00 00 01 25 16 11 04 a2 25 17 7e ?? 00 00 0a a2 25 18 07 a2 25 19 17 8c 04 00 00 01 a2 13 06}  //weight: 5, accuracy: Low
        $x_1_3 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAV_2147832377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAV!MTB"
        threat_id = "2147832377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {14 14 18 8d 01 00 00 01 25 16 7e a3 00 00 04 74 06 00 00 01 a2 25 17 02 7b a1 00 00 04 a2 28 00 01 00 06 26 2a}  //weight: 5, accuracy: High
        $x_2_2 = "Creat     eInsta    nce" wide //weight: 2
        $x_2_3 = "Syst        em.Acti        vator" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAW_2147832378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAW!MTB"
        threat_id = "2147832378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 13 16 13 15 11 13 28 ?? ?? 00 06 11 15 18 d6 5d 6f ?? 00 00 0a 11 15 17 d6 13 15 11 15 1f 0a 31 e3}  //weight: 5, accuracy: Low
        $x_5_2 = {11 13 1b 11 13 1b 6f ?? 00 00 0a 1f 19 d8 1f 19 d8 6f}  //weight: 5, accuracy: Low
        $x_2_3 = "{0}://{1}.{2}.{3}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAX_2147832564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAX!MTB"
        threat_id = "2147832564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 7e 01 00 00 04 02 7e 01 00 00 04 02 91 20 29 02 00 00 59 d2 9c 2a}  //weight: 5, accuracy: High
        $x_3_2 = "cY0diQEm" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEAY_2147832565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEAY!MTB"
        threat_id = "2147832565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ED1186DF9F6" ascii //weight: 5
        $x_5_2 = "C263791F8C4" ascii //weight: 5
        $x_5_3 = "rtbLibraries.Text" wide //weight: 5
        $x_3_4 = "get_MessageCreateNPDFFilesInDir" ascii //weight: 3
        $x_3_5 = "RussiaVsUkraine" ascii //weight: 3
        $x_2_6 = "DebuggerHiddenAttribute" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBA_2147832823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBA!MTB"
        threat_id = "2147832823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 7e 03 00 00 04 11 07 7e 03 00 00 04 11 07 91 20 ca 02 00 00 59 d2 9c 00 11 07 17 58 13 07 11 07 7e 03 00 00 04 8e 69 fe 04 13 08 11 08 2d d0}  //weight: 5, accuracy: High
        $x_2_2 = "filetransfer.io/data-package/31Kg6kcE" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBB_2147832824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBB!MTB"
        threat_id = "2147832824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 1c 74 0c 00 00 1b 28 2d 01 00 06 11 1e 18 d6 5d 6f 79 00 00 0a 11 1e 17 d6 13 1e 11 1e 1f 0a 31 de}  //weight: 5, accuracy: High
        $x_2_2 = "xcvxveget21q" wide //weight: 2
        $x_2_3 = "VCXMU99" wide //weight: 2
        $x_2_4 = "{0}://{1}.{2}.{3}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBC_2147832827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBC!MTB"
        threat_id = "2147832827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 16 9a 26 16 2d f9 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 39 ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {d0 01 00 00 1b 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 28 ?? 00 00 0a 13 06}  //weight: 5, accuracy: Low
        $x_5_3 = {00 00 0a 7e 01 00 00 04 02 1a 58 08 6f ?? 00 00 0a 28 ?? 00 00 0a a5 01 00 00 1b 0b 11 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBD_2147832828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBD!MTB"
        threat_id = "2147832828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "logish.cfg" wide //weight: 5
        $x_5_2 = "Gladiator" ascii //weight: 5
        $x_5_3 = "AbyssWalker" ascii //weight: 5
        $x_5_4 = "NeedGolkonda" ascii //weight: 5
        $x_5_5 = "get_Sorcerer" ascii //weight: 5
        $x_5_6 = "get_Necromancer" ascii //weight: 5
        $x_5_7 = "killButt" ascii //weight: 5
        $x_5_8 = "NeedKernon" ascii //weight: 5
        $x_5_9 = "Select * From Win32_Process Where ParentProcessID={0}" wide //weight: 5
        $x_1_10 = "GetChildProcesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBE_2147832923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBE!MTB"
        threat_id = "2147832923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 08 09 11 04 28 57 00 00 06 28 55 00 00 06 00 28 54 00 00 06 28 56 00 00 06 28 53 00 00 06 00 07 06 28 52 00 00 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBF_2147832925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBF!MTB"
        threat_id = "2147832925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Memory Game - codedByMadi.NET" wide //weight: 5
        $x_5_2 = "You cannot put yourself in check!" wide //weight: 5
        $x_5_3 = "MatchingPairsGame.Properties" wide //weight: 5
        $x_5_4 = "c:\\Windows\\media\\chord.wav" wide //weight: 5
        $x_5_5 = "Alarm03.wav" wide //weight: 5
        $x_5_6 = "KidsCheering.wav" wide //weight: 5
        $x_1_7 = "$$method0x60005b3-1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBG_2147832926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBG!MTB"
        threat_id = "2147832926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "NoW****i*n*d*o*w*" wide //weight: 5
        $x_5_2 = "CalXXXXXXXXXXXXXXXXXName" wide //weight: 5
        $x_5_3 = "(s)(t)(n(e)(m)(u(g)(r(A)" wide //weight: 5
        $x_5_4 = "{}t{}uc{}ex{}E{}llehSe{}sU{}{}{}{}{}{}" wide //weight: 5
        $x_5_5 = "\\Start Menu\\Programs\\Startup" wide //weight: 5
        $x_5_6 = "''''''t'''''r'''''''a'''''t''''''S''''''" wide //weight: 5
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBH_2147833197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBH!MTB"
        threat_id = "2147833197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 7e bf 00 00 04 09 7e bf 00 00 04 09 91 20 a1 02 00 00 59 d2 9c 00 09 17 58 0d 09 7e bf 00 00 04 8e 69 fe 04 13 04 11 04 2d d5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBJ_2147833199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBJ!MTB"
        threat_id = "2147833199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 5b 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {07 16 07 8e 69 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_4_3 = "MJCKVKLUIOR" ascii //weight: 4
        $x_4_4 = "c0b2247023b1949745425ddd9bbdc6c4e" ascii //weight: 4
        $x_1_5 = "pbDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBK_2147833200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBK!MTB"
        threat_id = "2147833200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 28 56 00 00 0a 02 28 0f 00 00 06 73 0d 00 00 06 7b 07 00 00 04 02 28 61 00 00 06 20 00 01 00 00 14 14 14 28 69 00 00 06}  //weight: 5, accuracy: High
        $x_4_2 = "Debugger detected (Managed)" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBL_2147833201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBL!MTB"
        threat_id = "2147833201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$0fa6b8cf-21eb-46e7-b2a4-7ec5e5dbc734" ascii //weight: 5
        $x_3_2 = "NVCVXNJDFGJKDF.pdb" ascii //weight: 3
        $x_3_3 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBN_2147833298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBN!MTB"
        threat_id = "2147833298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 28 2b 00 00 0a 25 26 06 6f 2c 00 00 0a 25 26 0c 1f 61 6a 08 28 ?? 00 00 06 25 26 80 0b 00 00 04 2a}  //weight: 5, accuracy: Low
        $x_5_2 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBO_2147833497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBO!MTB"
        threat_id = "2147833497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 07 08 09 28 15 00 00 06 28 13 00 00 06 00 28 12 00 00 06 28 14 00 00 06 28 11 00 00 06 00 7e 04 00 00 04 06 28 10 00 00 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBP_2147833499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBP!MTB"
        threat_id = "2147833499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 7e 02 00 00 04 07 7e 02 00 00 04 07 91 20 9e 03 00 00 59 d2 9c 00 07 17 58 0b 07 7e 02 00 00 04 8e 69 fe 04 0c 08 2d d7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBQ_2147833502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBQ!MTB"
        threat_id = "2147833502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 5
        $x_5_2 = "SEZLSktHSkgk" wide //weight: 5
        $x_5_3 = "HFKJKGJH.exe" ascii //weight: 5
        $x_2_4 = "pbDebuggerPresent" ascii //weight: 2
        $x_2_5 = "OpenProcess" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBS_2147834127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBS!MTB"
        threat_id = "2147834127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 28 bb 01 00 06 72 05 00 00 70 28 09 00 00 06 0a 06 28 18 00 00 0a}  //weight: 10, accuracy: High
        $x_5_2 = "SAFSAFSSAFSAFSFSAFSAFSA" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBT_2147834186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBT!MTB"
        threat_id = "2147834186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 08 09 11 04 28 ?? 00 00 06 28 ?? 00 00 06 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 00 07 06 28 ?? 00 00 06 d2 6f ?? 00 00 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBU_2147834400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBU!MTB"
        threat_id = "2147834400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 37 00 00 0a 06 6f 36 00 00 0a 25 26 0c 1f 61 6a 08 28 8f 00 00 06 25 26}  //weight: 5, accuracy: High
        $x_3_2 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 3
        $x_3_3 = "LogicNP Software 2009" ascii //weight: 3
        $x_1_4 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBX_2147834795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBX!MTB"
        threat_id = "2147834795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 26 25 1f 1c 28 ?? 00 00 06 20 82 00 00 00 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_5_2 = {a2 25 1f 24 28 ?? 00 00 06 28 ?? 00 00 0a 25 26 a2 25 1f 28}  //weight: 5, accuracy: Low
        $x_2_3 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBY_2147834796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBY!MTB"
        threat_id = "2147834796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 8d 1e 00 00 01 13 04 7e 2e 00 00 04 02 1a 58 11 04 16 08 28 34 00 00 0a 28 71 00 00 0a 11 04 16 11 04 8e 69}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECA_2147834798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECA!MTB"
        threat_id = "2147834798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 37 00 00 0a 02 07 17 58 02 8e 69 5d 91 28 38 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECC_2147835134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECC!MTB"
        threat_id = "2147835134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 14 14 2b 11 74 ?? 00 00 01 2b 11 16 2d da 16 2d d7 2a 02 2b db 6f ?? 00 00 0a 2b e8 28 ?? 00 00 0a 2b e8}  //weight: 5, accuracy: Low
        $x_5_2 = {00 00 0a 13 04 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 6f ?? 00 00 0a 16 6a 31 3d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECF_2147835138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECF!MTB"
        threat_id = "2147835138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 05 2b 0a 2b 0f 2a 28 ?? 00 00 0a 2b f4 28 ?? 00 00 2b 2b ef 28 ?? 00 00 2b 2b ea}  //weight: 5, accuracy: Low
        $x_5_2 = {11 08 17 58 13 08 11 08 11 07 8e 69 32 c4 2a 73 ?? 00 00 0a 38 13 ff ff ff 0a 38 12 ff ff ff 28 ?? 00 00 0a 38 0d ff ff ff 28 ?? 00 00 06 38 08 ff ff ff 6f ?? 00 00 0a 38 03 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECG_2147835139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECG!MTB"
        threat_id = "2147835139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 74 14 00 00 01 72 ?? 00 00 70 20 00 01 00 00 14 14 14 6f 22 00 00 0a 74 22 00 00 01 28 23 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_2_2 = "Fight" ascii //weight: 2
        $x_1_3 = "System.Reflection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECH_2147835140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECH!MTB"
        threat_id = "2147835140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 2a 00 28 ?? 00 00 06 28 ?? 00 00 0a 13 00 38 00 00 00 00 dd e6 ff ff ff 26 38 00 00 00 00 14 13 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECD_2147835448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECD!MTB"
        threat_id = "2147835448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "a.pomf.cat" wide //weight: 10
        $x_5_2 = "19.10.20069.49826" ascii //weight: 5
        $x_2_3 = "Powered by SmartAssembly 8.1.0.4892" ascii //weight: 2
        $x_1_4 = "Adobe Acrobat DC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEBZ_2147835901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEBZ!MTB"
        threat_id = "2147835901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 2b 16 06 09 28 ?? 00 00 06 13 04 07 09 11 04 6f ?? 00 00 0a 09 18 58 0d 09 06 6f ?? 00 00 0a 32 e1}  //weight: 5, accuracy: Low
        $x_5_2 = {02 03 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECK_2147835903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECK!MTB"
        threat_id = "2147835903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {18 16 2c 4b 26 2b 32 06 07 9a 16 2c 45 26 08 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 28 03 00 00 0a 33 0a 17 25}  //weight: 10, accuracy: Low
        $x_5_2 = "SmartAssembly.HouseOfCards" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECL_2147835907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECL!MTB"
        threat_id = "2147835907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 06 04 03 8e 69 14 14 17 28 ?? ?? 00 06 d6 13 07 11 07 04 5f 13 08 03 11 06 03 8e 69 14 14 17 28 ?? ?? 00 06 91 13 09 08 11 06 16 16 02 17 8d 03 00 00 01 25 16 11 06 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 16 16 11 09}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NZL_2147836232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NZL!MTB"
        threat_id = "2147836232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sddddffshdjfffffgjskdgsacsafp" ascii //weight: 1
        $x_1_2 = "ffchkffaffsdssfj" ascii //weight: 1
        $x_1_3 = "jsfhdgffffdffdkfgfgj" ascii //weight: 1
        $x_1_4 = "hsfjfgfhsddfdffhf" ascii //weight: 1
        $x_1_5 = "jddssssssssssssssdfsssssssffsddhfhkfj" ascii //weight: 1
        $x_1_6 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECO_2147836319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECO!MTB"
        threat_id = "2147836319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 07 11 09 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d db 08 6f ?? 00 00 0a 0d 09 28 ?? 00 00 0a 13 04 11 04 6f ?? 00 00 0a 17 9a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECP_2147836322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECP!MTB"
        threat_id = "2147836322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 22 00 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 06 07 1a 5d 1f 0a 5a 91 61 d2 81 ?? 00 00 01 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECQ_2147836323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECQ!MTB"
        threat_id = "2147836323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 06 11 08 9a 1f 10 28 74 00 00 0a 8c 54 00 00 01 6f 75 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d d6 07 d0 54 00 00 01 28 50 00 00 0a 6f 76 00 00 0a 74 03 00 00 1b 0c 28 77 00 00 0a 08 6f 78 00 00 0a 0d 09}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECR_2147836507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECR!MTB"
        threat_id = "2147836507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 07 11 09 9a 1f 10 28 6e 00 00 0a 8c 58 00 00 01 6f 6f 00 00 0a 26 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d d6 08 d0 58 00 00 01 28 3c 00 00 0a 6f 70 00 00 0a 74 01 00 00 1b 0d 09 28 71 00 00 0a 13 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECS_2147836509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECS!MTB"
        threat_id = "2147836509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 06 08 06 6f 19 00 00 0a 1e 5b 6f 1a 00 00 0a 6f 1b 00 00 0a 06 08 06 6f 1c 00 00 0a 1e 5b 6f 1a 00 00 0a 6f 1d 00 00 0a 06 17 6f 1e 00 00 0a}  //weight: 10, accuracy: High
        $x_5_2 = {11 04 09 16 09 8e 69 6f ?? 00 00 0a de 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECT_2147836510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECT!MTB"
        threat_id = "2147836510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 08 07 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 50 16 02 50 8e 69 6f ?? 00 00 0a 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECU_2147836513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECU!MTB"
        threat_id = "2147836513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 08 06 11 08 9a 1f 10 28 ?? 00 00 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de 07 28 ?? 00 00 0a 0d 09}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECY_2147837211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECY!MTB"
        threat_id = "2147837211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "561e7a93-d222-4cbd-abc0-59c70e8b74ed" ascii //weight: 5
        $x_5_2 = "_2048WindowsFormsApp.RulesOfTheGameForm.resources" ascii //weight: 5
        $x_5_3 = "mapSize5x5ToolStripMenuItem_Click" ascii //weight: 5
        $x_2_4 = "AllScoresForm_Load" ascii //weight: 2
        $x_2_5 = "get_text_x_rpm_spec" ascii //weight: 2
        $x_1_6 = "CASCX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NECZ_2147837212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NECZ!MTB"
        threat_id = "2147837212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 07 11 08 9a 1f 10 28 4e 00 00 0a 6f 4f 00 00 0a 00 11 08 17 58 13 08 11 08 20 00 ea 00 00 fe 04 13 09 11 09 2d d9 28 50 00 00 0a 08 6f 51 00 00 0a 6f 52 00 00 0a 0d 09}  //weight: 10, accuracy: High
        $x_5_2 = "FamilyBudgetManagement" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDA_2147837432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDA!MTB"
        threat_id = "2147837432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cc7fad03-816e-432c-9b92-001f2d358386" ascii //weight: 10
        $x_5_2 = "server1.exe" ascii //weight: 5
        $x_1_3 = "ConfuserEx v1.0.0" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "get_Target" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AVE_2147837822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AVE!MTB"
        threat_id = "2147837822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 17 00 00 01 25 16 72 de 68 02 70 a2 25 17 72 e4 68 02 70 a2 14 14 14 28}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Perpustakaan" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDC_2147837830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDC!MTB"
        threat_id = "2147837830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 34 16 2b 34 2b 39 2b 3e 2b 09 2b 0a 2b 0b 16 2d f7 de 17 09 2b f4 08 2b f3 6f ?? 00 00 0a 2b ee 09 2c 06 09 6f ?? 00 00 0a dc 2b 1d 6f ?? 00 00 0a 13 04 de 60 07 2b c9}  //weight: 10, accuracy: Low
        $x_2_2 = "Powered by SmartAssembly 8.1.0.4892" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDD_2147837834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDD!MTB"
        threat_id = "2147837834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0a 2b 6a 00 28 04 00 00 06 73 1a 00 00 0a 0b 73 15 00 00 0a 0c 07 16 73 1b 00 00 0a 73 1c 00 00 0a 0d 09 08 6f 17 00 00 0a de 0a 09 2c 06 09 6f 1d 00 00 0a dc 08 6f 18 00 00 0a 13 04 de 34 08 2c 06 08}  //weight: 10, accuracy: High
        $x_2_2 = "Client Session Agent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDG_2147838270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDG!MTB"
        threat_id = "2147838270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "khnhFIc.exe" ascii //weight: 5
        $x_5_2 = "49d0b89f-1778-4fb1-817e-19c61a5c0213" ascii //weight: 5
        $x_2_3 = "U21hcnRBc3NlbWJseQ==" ascii //weight: 2
        $x_2_4 = "RVJSIDIwMDQ6IA==" ascii //weight: 2
        $x_2_5 = "VW5oYW5kbGVkRXhjZXB0aW9uUmVwb3J0" ascii //weight: 2
        $x_2_6 = "UmVwb3J0aW5nLmFzbXg=" ascii //weight: 2
        $x_2_7 = "U2h1dGRvd24=" ascii //weight: 2
        $x_2_8 = "Q291bGQgbm90IGRlc2VyaWFsaXplIHRoZSBvYmVjdA==" ascii //weight: 2
        $x_2_9 = "R2V0U2VydmVyVVJM" ascii //weight: 2
        $x_1_10 = "SmartAssembly.HouseOfCards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDH_2147838274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDH!MTB"
        threat_id = "2147838274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "9ef7d2b9-0df2-407a-a6a5-6a7e15e5f0ee" ascii //weight: 5
        $x_5_2 = "Yahtzee.FVUJHBSF" ascii //weight: 5
        $x_2_3 = "Yahtzee Scorboard" ascii //weight: 2
        $x_2_4 = "Mags Industries" ascii //weight: 2
        $x_2_5 = "MM Lingnau  2013" ascii //weight: 2
        $x_2_6 = "It is a game played with 5 dice and good friends" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDJ_2147838391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDJ!MTB"
        threat_id = "2147838391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 16 0a 2b 1b 00 7e ?? 00 00 04 06 7e ?? 00 00 04 06 91 20 ?? ?? 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7 7e ?? 00 00 04 0c 2b 00 08 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "https://filetransfer.io/data-package/" wide //weight: 5
        $x_1_3 = "System.Windows.Forms" ascii //weight: 1
        $x_1_4 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDM_2147838892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDM!MTB"
        threat_id = "2147838892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df 09 6f ?? 00 00 0a 13 05 de 21}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDN_2147838893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDN!MTB"
        threat_id = "2147838893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 25 2c 07 58 13 04 11 04 07 8e 69 16 2d fc 32 d9 1a 2c af 09 6f ?? 00 00 0a 13 05}  //weight: 10, accuracy: Low
        $x_5_2 = "Powered by SmartAssembly 8.1.2.4975" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDP_2147839077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDP!MTB"
        threat_id = "2147839077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "e78a7453-02a9-42bb-8d5a-c436765a5194" ascii //weight: 5
        $x_5_2 = "Efgqtbre.exe" ascii //weight: 5
        $x_3_3 = "Smart Install Maker 5.02 Installation" ascii //weight: 3
        $x_2_4 = "5.2.0.0" ascii //weight: 2
        $x_1_5 = "System.Collections.Generic" ascii //weight: 1
        $x_1_6 = "Confuser v1.9.0.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDQ_2147839078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDQ!MTB"
        threat_id = "2147839078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "6604189b-b3c7-45c0-b4af-b0ac0ebf0b58" ascii //weight: 5
        $x_3_2 = "3.58.4081.24586" ascii //weight: 3
        $x_3_3 = "Paint.NET" ascii //weight: 3
        $x_3_4 = "Debugger detected (Managed)" wide //weight: 3
        $x_1_5 = "Confuser v1.9.0.0" ascii //weight: 1
        $x_1_6 = "RPF:SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDS_2147839125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDS!MTB"
        threat_id = "2147839125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "bd97928a-761e-4833-95a4-f339cc65b964" ascii //weight: 4
        $x_4_2 = "Alexander Roshal" ascii //weight: 4
        $x_4_3 = "f8Q0RjCo42Jsx3S5YaP" ascii //weight: 4
        $x_1_4 = "Command line RAR" ascii //weight: 1
        $x_1_5 = "System.Windows.Forms.Automation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDT_2147839263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDT!MTB"
        threat_id = "2147839263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 2a 11 00 2a 00 d0 0d 00 00 01 28 05 00 00 0a 02 02 28 06 00 00 06 28 07 00 00 06 74 0b 00 00 01 72 3f 00 00 70 28 06 00 00 0a 6f 07 00 00 0a 16 9a 28 01 00 00 2b 6f 09 00 00 0a 26 20 01 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "Wdaayajrcp" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDU_2147839264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDU!MTB"
        threat_id = "2147839264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 16 13 04 2b 1e 09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? 00 00 0a 11 04 13 05 11 05 17 58 13 04 11 04 08 8e 69 32 db 09 6f ?? 00 00 0a 13 06 de 1b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDX_2147839267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDX!MTB"
        threat_id = "2147839267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 9c 11 04 03 6f ?? 00 00 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 cd}  //weight: 10, accuracy: Low
        $x_5_2 = "pr0t0typ3" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDW_2147839463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDW!MTB"
        threat_id = "2147839463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 13 00 00 0a 72 67 00 00 70 28 0b 00 00 06 6f 14 00 00 0a 28 15 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 0b dd 1d 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "bllsl1.shop" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDY_2147839465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDY!MTB"
        threat_id = "2147839465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "%%t\\D$\\debug.exe" wide //weight: 5
        $x_5_2 = "%%t\\e$\\shared\\debug.exe" wide //weight: 5
        $x_5_3 = "%%t\\PRINT$\\debug.exe" wide //weight: 5
        $x_5_4 = "%%t\\ADMIN$\\debug.exe" wide //weight: 5
        $x_5_5 = "%%t\\IPC$\\debug.exe" wide //weight: 5
        $x_5_6 = "\\autorun.inf" wide //weight: 5
        $x_5_7 = "net view >log.txt" wide //weight: 5
        $x_5_8 = "Klepassfile" wide //weight: 5
        $x_1_9 = "get_ProcessName" ascii //weight: 1
        $x_1_10 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_11 = "System.Windows.Forms" ascii //weight: 1
        $x_1_12 = "Invoke" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEDZ_2147839721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEDZ!MTB"
        threat_id = "2147839721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 0a 1a 2d 1d 26 07 28 ?? 00 00 0a 0c 08 16 08 8e 69 28 ?? 00 00 0a 08 0d de 25 28 ?? 00 00 0a 2b db 0b 2b e1 26 20 88 13 00 00 28 ?? 00 00 0a de 00 06 13 04 11 04 17 58 0a 06 1b 32 a4 14 2a 09 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEA_2147839740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEA!MTB"
        threat_id = "2147839740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 2a 16 2c 2e 26 2b 2e 2b 2f 2b 34 16 2d f7 2b 32 16 08 8e 69 28 ?? 00 00 0a 08 0d de 52 28 ?? 00 00 0a 2b c9 28 ?? 00 00 0a 2b d4 6f ?? 00 00 0a 2b cf 0b 2b d0 07 2b cf 28 ?? 00 00 0a 2b ca 0c 2b c9 08 2b cb}  //weight: 10, accuracy: Low
        $x_2_2 = "SmartAssembly.Attributes" ascii //weight: 2
        $x_2_3 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEB_2147839875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEB!MTB"
        threat_id = "2147839875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "A3DD3CCDDF9DE0CD92C45652E4F557C3CD4C9DF25AAA376ED8E8BB0CF592E246" ascii //weight: 5
        $x_5_2 = "Brgy_Daang_Bukid_MIS.Resources.resources" ascii //weight: 5
        $x_5_3 = "FG@ABCDEFf" ascii //weight: 5
        $x_2_4 = "My.MyProject.Forms" ascii //weight: 2
        $x_2_5 = "TargetInvocationException" ascii //weight: 2
        $x_2_6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii //weight: 2
        $x_2_7 = "System.Windows.Forms.Form" ascii //weight: 2
        $x_2_8 = "InvokeMember" ascii //weight: 2
        $x_2_9 = "set_Visible" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEC_2147839966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEC!MTB"
        threat_id = "2147839966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bbff2a71-7db6-4243-8acb-d38c32bc310d" ascii //weight: 5
        $x_5_2 = "kLjw4iIsCLsZtxc4lksN0j" ascii //weight: 5
        $x_5_3 = "WindowsDataC.exe" wide //weight: 5
        $x_2_4 = "mini calculator.exe" ascii //weight: 2
        $x_2_5 = "mini_calculator.My" ascii //weight: 2
        $x_1_6 = "Invoke" ascii //weight: 1
        $x_1_7 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEED_2147840469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEED!MTB"
        threat_id = "2147840469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c863717e-961a-498b-8399-b06a2876b043" ascii //weight: 5
        $x_2_2 = "TagsOfSentence" ascii //weight: 2
        $x_2_3 = "GrammersOfSentence" ascii //weight: 2
        $x_2_4 = "GrammersPossible" ascii //weight: 2
        $x_2_5 = "Alladin Realty 2023" ascii //weight: 2
        $x_2_6 = "Database1.sdf" ascii //weight: 2
        $x_2_7 = "DebuggerHiddenAttribute" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEE_2147840470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEE!MTB"
        threat_id = "2147840470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bee4a6ff-9e64-424d-8f97-fe73d6fd02f0" ascii //weight: 5
        $x_2_2 = "Calculator.exe" ascii //weight: 2
        $x_2_3 = "Emil Sayahi" ascii //weight: 2
        $x_2_4 = "get_ExecutablePath" ascii //weight: 2
        $x_1_5 = "RPF:SmartAssembly" ascii //weight: 1
        $x_1_6 = "StrReverse" ascii //weight: 1
        $x_1_7 = "My.MyProject.Forms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEJ_2147841311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEJ!MTB"
        threat_id = "2147841311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 03 8e 69 17 59 17 58 0c 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 ?? 00 00 0a 03 04 17 58 08 5d 91 28 ?? 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEK_2147841312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEK!MTB"
        threat_id = "2147841312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "92887554-02bf-44d0-a6f4-6a0ef35f7998" ascii //weight: 5
        $x_2_2 = "CSE535.keymn.resources" ascii //weight: 2
        $x_2_3 = "CSE535.Frvarible.resources" ascii //weight: 2
        $x_2_4 = "Romp 2023" ascii //weight: 2
        $x_1_5 = "levenshtein1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEI_2147841428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEI!MTB"
        threat_id = "2147841428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 09 07 28 04 00 00 0a 13 0a 11 0a 28 05 00 00 0a 7e 06 00 00 04 6f 06 00 00 0a 7e 07 00 00 04}  //weight: 10, accuracy: High
        $x_5_2 = "C:\\\\Windows\\\\Microsoft.NET\\\\Framework\\\\v4.0.30319" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEP_2147841465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEP!MTB"
        threat_id = "2147841465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {28 05 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 72 ?? 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b de 03 26 de cf}  //weight: 10, accuracy: Low
        $x_2_2 = "DynamicInvoke" ascii //weight: 2
        $x_2_3 = "GetByteArrayAsync" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEES_2147842212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEES!MTB"
        threat_id = "2147842212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 1f 2d 9d 6f ?? 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0c 16 13 05 2b 18 00 08 11 05 07 11 05 9a 1f 10 28 ?? 00 00 0a d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db 02}  //weight: 10, accuracy: Low
        $x_2_2 = "WMPLib._WMPOCXEvents" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEU_2147842215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEU!MTB"
        threat_id = "2147842215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 16 0b 2b 22 00 06 6f ?? 00 00 0a 07 9a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 2c 02 de 0e de 03 26 de 00 07 17 58 0b 07}  //weight: 10, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "System.Reflection" ascii //weight: 1
        $x_1_4 = "System.Net.Http" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEV_2147842279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEV!MTB"
        threat_id = "2147842279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 14 2b 19 2b 1e 17 2d 06 26 16 2d 04 de 22 2b 1a 19 2c ec 2b f4 28 ?? 00 00 06 2b e5 28 ?? 00 00 2b 2b e0 28 ?? 00 00 2b 2b db 0a 2b e3}  //weight: 10, accuracy: Low
        $x_2_2 = "Powered by SmartAssembly 8.1.2.4975" ascii //weight: 2
        $x_2_3 = "Invoke" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEW_2147842282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEW!MTB"
        threat_id = "2147842282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 28 0e 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b de 03 26 de d9 07 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 2
        $x_2_3 = "DynamicInvoke" ascii //weight: 2
        $x_2_4 = "Reverse" ascii //weight: 2
        $x_2_5 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RE_2147842330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RE!MTB"
        threat_id = "2147842330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0d 06 08 94 13 04 06 08 06 09 94 9e 06 09 11 04 9e 00 08 17 59 0c 08 16 fe 02 13 05 11 05 2d d6 06 13 06 2b 00 11 06 2a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEY_2147843077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEY!MTB"
        threat_id = "2147843077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 02 03 02 8e 69 5d 91 06 03 06 8e 69 5d 91 61 28 ?? 00 00 0a 02 03 17 d6 02 8e 69 5d 91 28 ?? 00 00 0a da}  //weight: 10, accuracy: Low
        $x_2_2 = "Qta.BitmapView.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEZ_2147843106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEZ!MTB"
        threat_id = "2147843106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 0c dd 06 00 00 00 26}  //weight: 10, accuracy: Low
        $x_2_2 = "Serilog.Sinks.DiagnosticTrace" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEFA_2147843187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEFA!MTB"
        threat_id = "2147843187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6f 59 00 00 0a 80 28 00 00 04 16 0b 2b 1b 00 7e ?? 00 00 04 07 7e ?? 00 00 04 07 91 20 ?? ?? 00 00 59 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe 04 0c 08 2d d7 7e ?? 00 00 04 0d 2b 00 09 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "Seio.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEEO_2147843344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEEO!MTB"
        threat_id = "2147843344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 07 75 15 00 00 01 14 17 8d 02 00 00 01 25 16 03 a2 6f 80 00 00 0a 74 42 00 00 01 13 08 1b 13 0e 2b be}  //weight: 10, accuracy: High
        $x_5_2 = "annot ye run" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEFC_2147843865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEFC!MTB"
        threat_id = "2147843865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 05 9a 13 09 11 04 11 09 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 05 17 d6 13 05 00 11 05 09 8e 69 fe 04 13 0a 11 0a 2d d4 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 11 06 6f ?? 00 00 0a 16 9a 13 07 11 07}  //weight: 10, accuracy: Low
        $x_2_2 = "Nude_Photos" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEFD_2147843866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEFD!MTB"
        threat_id = "2147843866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 16 09 16 1e 28 ?? 00 00 0a 00 07 09 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 05 11 05 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "Confuser.Core 1.6" ascii //weight: 2
        $x_2_3 = "set_WindowStyle" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEFG_2147844263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEFG!MTB"
        threat_id = "2147844263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 16 0b 2b 32 00 16 0c 2b 19 00 03 07 08 6f ?? 00 00 0a 0d 06 07 12 03 28 ?? 00 00 0a 9c 00 08 17 58 0c 08 03 6f ?? 00 00 0a fe 04 13 04 11 04 2d d8 00 07 17 58 0b 07 03 6f ?? 00 00 0a fe 04 13 05 11 05 2d bf 06 13 06 2b 00 11 06}  //weight: 10, accuracy: Low
        $x_2_2 = "DungeonGame" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NLM_2147845308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NLM!MTB"
        threat_id = "2147845308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 6a 00 00 0a 13 05 1a 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 25 18 72 ?? ?? ?? 70 a2 25 19 72 ?? ?? ?? 70 a2 13 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Quantum.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NLM_2147845308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NLM!MTB"
        threat_id = "2147845308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 7c 00 00 01 25 16 03 9d 6f ?? ?? 00 0a 7e ?? ?? 00 04 25 2d 17 26 7e ?? ?? 00 04 fe ?? ?? ?? ?? 06 73 ?? ?? 00 0a 25 80 ?? ?? 00 04 28 ?? ?? 00 2b}  //weight: 5, accuracy: Low
        $x_1_2 = "ds_agent_oriented_simulation.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_FAT_2147845853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.FAT!MTB"
        threat_id = "2147845853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 2c 66 26 11 05 11 04 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 11 06 07 16 07 8e 69 6f ?? 00 00 0a 13 07 28 ?? 00 00 0a 11 07 6f ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 13 0a de 2d}  //weight: 3, accuracy: Low
        $x_1_2 = "hkgfffgsfddfffdhhddrfdahfddsshcf" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NEFI_2147847435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NEFI!MTB"
        threat_id = "2147847435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c3d6176e-490d-4578-806a-09754b4b3866" ascii //weight: 5
        $x_2_2 = "SafeGameWinForms" ascii //weight: 2
        $x_2_3 = "Lab2_Anagram.frmMainWindow.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NA_2147847494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NA!MTB"
        threat_id = "2147847494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 8b 00 00 0a 6f 3b 00 00 06 0c 28 08 00 00 06 6f 85 00 00 0a 09 72 19 01 00 70 06 18 9a 28 8c 00 00 0a 07 16 6f 8d 00 00 0a 00 28 08 00 00 06 6f 85 00 00 0a}  //weight: 3, accuracy: High
        $x_1_2 = {13 04 00 28 8f 00 00 0a 6f 90 00 00 0a 00 28 38 00 00 0a}  //weight: 1, accuracy: High
        $x_1_3 = "stub.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NA_2147847494_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NA!MTB"
        threat_id = "2147847494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 08 00 00 0a 6f ?? 00 00 0a 14 17 8d ?? 00 00 01 25 16 07 a2 6f ?? 00 00 0a 75 ?? 00 00 1b 08 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp40.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NG_2147847496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NG!MTB"
        threat_id = "2147847496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0b 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 75 ?? 00 00 1b 0b 07 16 07 8e 69 28 ?? 00 00 0a 07 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp39.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "Bazsiex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NT_2147847497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NT!MTB"
        threat_id = "2147847497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 75 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "POMNB876.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NVA_2147847499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NVA!MTB"
        threat_id = "2147847499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 1f 20 28 13 00 00 06 73 ?? ?? ?? 0a 0b 07 03 1f 24 28 ?? ?? ?? 06 03 8e 69 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "POMNB876.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_PSOX_2147847871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.PSOX!MTB"
        threat_id = "2147847871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 20 00 0c 00 00 28 ?? ?? ?? 0a 00 7e 3d 00 00 04 72 9e 08 00 70 6f ?? ?? ?? 0a 80 3e 00 00 04 16 0a 2b 1b 00 7e 3e 00 00 04 06 7e 3e 00 00 04 06 91 20 36 03 00 00 59 d2 9c 00 06 17 58 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NMA_2147848256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NMA!MTB"
        threat_id = "2147848256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 18 20 a2 e7 3f 61 5a 20 ?? ?? ?? a8 61 38 ?? ?? ?? ff 7e ?? ?? ?? 04 7e ?? ?? ?? 04 28 ?? ?? ?? 06 20 ?? ?? ?? 09 38 ?? ?? ?? ff 11 17 17 58 13 17 20 ?? ?? ?? 7e}  //weight: 5, accuracy: Low
        $x_1_2 = "BHNh772" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NMA_2147848256_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NMA!MTB"
        threat_id = "2147848256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 16 0d 11 06 20 ?? ?? ?? cd 5a 20 ?? ?? ?? 34 61 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 20 ?? ?? ?? 18 28 ?? ?? ?? 2b 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "CC01.frmDanhSachSanPham.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NMA_2147848256_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NMA!MTB"
        threat_id = "2147848256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 04 00 00 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 13 0b 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff 00 11 0b 11 01 17 73 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "QUOTATIONLISTFORTURKMENISTAN.Dictionaries" ascii //weight: 1
        $x_1_3 = "Slzsmqar.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NAH_2147848438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NAH!MTB"
        threat_id = "2147848438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 99 02 00 06 8c ?? ?? ?? 01 73 ?? ?? ?? 0a a2 25 1f 0d 20 ?? ?? ?? b2 28 ?? ?? ?? 06 04 6f ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Winforms_XML.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_ABYB_2147848454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.ABYB!MTB"
        threat_id = "2147848454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 00 02 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 11 04 11 05 28 ?? 00 00 2b 28 ?? 00 00 2b 13 06 de 2c 09 2c 07 09 6f ?? 00 00 0a 00 dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NAA_2147848621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NAA!MTB"
        threat_id = "2147848621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 20 1f d8 36 76 5a 20 ?? ?? ?? 98 61 38 ?? ?? ?? ff 00 07 20 ?? ?? ?? 5f 5a 20 ?? ?? ?? 69 61 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 1a 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "AirportBaggage.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NAA_2147848621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NAA!MTB"
        threat_id = "2147848621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 9c 00 00 06 0d 7e ?? ?? ?? 04 09 02 16 02 8e 69 28 ?? ?? ?? 06 2a 73 ?? ?? ?? 0a 38 ?? ?? ?? ff 0a 38 ?? ?? ?? ff 0b 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 38 ?? ?? ?? ff 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_5_2 = {06 1f 20 02 7e ?? ?? 00 04 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 06 0a 02 7b ?? ?? 00 04 14 06 28 ?? ?? 00 06 26 20 ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = "AhfFlkkAS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NAA_2147848621_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NAA!MTB"
        threat_id = "2147848621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 8b 01 00 06 61 7e ?? ?? 00 04 28 ?? ?? 00 06 11 01 11 03 17 58 11 01 8e 69 5d 91 7e ?? ?? 00 04 28 ?? ?? 00 06 59 20 ?? ?? 00 00 58 20 ?? ?? 00 00 5d 7e ?? ?? 00 04 28 ?? ?? 00 06 9c}  //weight: 5, accuracy: Low
        $x_1_2 = "kCsK.g.resources" ascii //weight: 1
        $x_1_3 = "ExitExamApp.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NAR_2147849143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NAR!MTB"
        threat_id = "2147849143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 05 00 00 04 6f ?? 00 00 0a 02 16 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07}  //weight: 5, accuracy: Low
        $x_1_2 = "Uppgift4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MBGG_2147850558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MBGG!MTB"
        threat_id = "2147850558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0f 11 01 16 73 ?? 00 00 0a 13 0c 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? 00 00 00 26 20 00 00 00 00 38 ?? 00 00 00 fe 0c 05 00}  //weight: 1, accuracy: Low
        $x_1_2 = "b-86e1-683974fccb61" ascii //weight: 1
        $x_1_3 = "Tzhac.Properties.Resources.resource" ascii //weight: 1
        $x_1_4 = "Ouvx2MBuw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MBGL_2147850563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MBGL!MTB"
        threat_id = "2147850563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 2b 29 11 07 06 08 58 07 09 58 6f ?? 00 00 0a 13 0f 12 0f 28 ?? 00 00 0a 13 09 11 05 11 04 11 09 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0a 11 0a 2d cd}  //weight: 1, accuracy: Low
        $x_1_2 = {13 06 16 13 04 20 01 5c 00 00 8d ?? 00 00 01 13 05 11 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RDC_2147850785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RDC!MTB"
        threat_id = "2147850785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3309cae8-cd3c-4cd1-b22c-6d920211c8a4" ascii //weight: 1
        $x_1_2 = "ChiTietPhieuThue" ascii //weight: 1
        $x_1_3 = "frmBangDia" ascii //weight: 1
        $x_1_4 = "QuanLyBangDiaCD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_PSSR_2147851255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.PSSR!MTB"
        threat_id = "2147851255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 70 a2 25 19 28 ?? 00 00 06 a2 25 1a 72 7b 00 00 70 a2 25 1b 28 ?? 00 00 06 a2 25 1c 72 95 00 00 70 a2 25 1d 28 ?? 00 00 06 a2 28 ?? 00 00 0a 6f ?? 00 00 0a 80 03 00 00 04 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NCA_2147851392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NCA!MTB"
        threat_id = "2147851392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 02 8c 5c 00 00 01 a2 25 0b 14 14 17 8d ?? ?? ?? 01 25 16 17 9c 25 0c 28 ?? ?? ?? 0a 0d 1a 13 05 38 ?? ?? ?? ff 08 74 ?? ?? ?? 1b 16 91 2d 08 19 13 05 38 ?? ?? ?? ff 1e 2b f6 1d 13 05 38 ?? ?? ?? ff 07 74 ?? ?? ?? 1b 16 9a 28 ?? ?? ?? 0a d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a a5 ?? ?? ?? 01}  //weight: 5, accuracy: Low
        $x_1_2 = "6f4bedcb517067.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RDD_2147851680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RDD!MTB"
        threat_id = "2147851680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "63c54a94-bed2-453e-8a39-ed9dc8a70618" ascii //weight: 1
        $x_1_2 = "Asdbuge Facka" ascii //weight: 1
        $x_1_3 = "ATM_simulation" ascii //weight: 1
        $x_1_4 = "Cannon_Simulation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NAV_2147851880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NAV!MTB"
        threat_id = "2147851880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 00 01 00 00 6f ?? ?? 00 0a 06 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 06 6f ?? ?? 00 0a 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0b 73 ?? ?? 00 0a 0c 08 07 17 73 ?? ?? 00 0a 0d 28 ?? ?? 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? ?? 00 0a 08 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Okkfnvxd.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AAMA_2147888503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AAMA!MTB"
        threat_id = "2147888503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 19 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MBIB_2147888875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MBIB!MTB"
        threat_id = "2147888875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$58b901d7-d365-4e7f-b460-3642d6ac7946" ascii //weight: 1
        $x_1_2 = "QLGV_Winform.Properties.Resources.resource" ascii //weight: 1
        $x_1_3 = {40 01 57 dd a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "GetMethod" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "ToInt32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RPY_2147890356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RPY!MTB"
        threat_id = "2147890356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 06 09 11 06 91 20 37 07 00 00 59 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RPY_2147890356_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RPY!MTB"
        threat_id = "2147890356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 15 09 5d 13 16 11 15 11 04 5d 13 17 07 11 16 91 13 18 08 11 17}  //weight: 1, accuracy: High
        $x_1_2 = {13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c 00 11 15 17 59 13 15 11 15 16 fe 04 16 fe 01 13 1c 11 1c 2d a9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NC_2147892305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NC!MTB"
        threat_id = "2147892305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 74 3f 00 70 d0 ?? ?? 00 02 28 ?? ?? 00 0a 6f ?? ?? 00 0a 73 ?? ?? 00 0a 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "Iolhe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AARV_2147892570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AARV!MTB"
        threat_id = "2147892570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 06 2b 3d 7e ?? 00 00 04 11 06 7e ?? 00 00 04 11 06 91 7e ?? 00 00 04 61 7e ?? 00 00 04 09 91 61 28 ?? 00 00 06 9c 09 7e ?? 00 00 04 8e 69 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 06 17 58 13 06 11 06 7e ?? 00 00 04 8e 69 17 59 31 b6}  //weight: 4, accuracy: Low
        $x_1_2 = "CSharpGoWinForm.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AAVE_2147895176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AAVE!MTB"
        threat_id = "2147895176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 19 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 03 16 03 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MBEG_2147895191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MBEG!MTB"
        threat_id = "2147895191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sgfhjffffdrfhddfhfffakdfsfsscfgdb" ascii //weight: 1
        $x_1_2 = "sgfhjfffgdrfhddhfffadfsfsscfgdb" ascii //weight: 1
        $x_1_3 = "djfflsfhgdffafcfdssfkfhgj" ascii //weight: 1
        $x_1_4 = "ffchkffldfhfdsfsfj" ascii //weight: 1
        $x_1_5 = "hdfffffafsdkfsh" ascii //weight: 1
        $x_1_6 = "RijndaelManaged" ascii //weight: 1
        $x_1_7 = "hffffdshdhs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MBEH_2147895304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MBEH!MTB"
        threat_id = "2147895304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 64 64 66 66 68 6b 65 64 66 64 64 66 66 66 66 67 6a 66 73 66 6b 64 67 73 61 63 73 61 66 70 00 73 67 66 68 6a 66 66 66 66 64 72 66 68 64 64 66 68 66 66 66 61 6b 64 66 73 66 73 73 63 66 67 64 62 00 64 6a 66 66 66 6b 68 67 64 66 66 61 66 63 66 64 73 73 66 6b 66 68 67 6a 00 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AAVM_2147895399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AAVM!MTB"
        threat_id = "2147895399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 17 9a 74 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 16 0d 2b 16 00 08 09 08 09 91 06 18 9a a5 ?? 00 00 01 59 d2 9c 00 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AAVH_2147895736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AAVH!MTB"
        threat_id = "2147895736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdddffhedfddffffgjfskdgsacsafp" ascii //weight: 1
        $x_1_2 = "sgfhjfffgdrfhddhfffadfsfsscfgdb" ascii //weight: 1
        $x_1_3 = "djsfhgdffafcfdssfkfhgj" ascii //weight: 1
        $x_1_4 = "ffchkfdahfdsfsfj" ascii //weight: 1
        $x_1_5 = "fdfcffrdgfdfsfsffj" ascii //weight: 1
        $x_1_6 = "hdfffffafsdkfsh" ascii //weight: 1
        $x_1_7 = "hdfffhfdffffkdf" ascii //weight: 1
        $x_1_8 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AAWX_2147896926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AAWX!MTB"
        threat_id = "2147896926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 1b 00 7e ?? 00 00 04 07 7e ?? 00 00 04 07 91 20 ?? 07 00 00 59 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe 04 0c 08 2d d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AAYJ_2147898291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AAYJ!MTB"
        threat_id = "2147898291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 03 08 1c 58 1b 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_NRA_2147899462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.NRA!MTB"
        threat_id = "2147899462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 7e 02 00 00 04 06 7e ?? ?? ?? 04 06 91 20 ?? ?? ?? 00 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: Low
        $x_1_2 = "ControlWin.Progress.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MA_2147900027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MA!MTB"
        threat_id = "2147900027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0c 08 16 08 8e 69 28 17 00 00 0a 08 0d de 0a 07 2c 06 06 28 18 00 00 0a dc}  //weight: 5, accuracy: High
        $x_5_2 = {9e 07 06 11 05 94 58 0b 11 05 17 58 13 05 11 05 1f 0a 32 c0}  //weight: 5, accuracy: High
        $x_2_3 = "DownloadData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_MA_2147900027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.MA!MTB"
        threat_id = "2147900027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 95 a2 29 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 44 00 00 00 11}  //weight: 10, accuracy: High
        $x_1_2 = "lld.eerocsm" ascii //weight: 1
        $x_1_3 = "niaMllDroC_" ascii //weight: 1
        $x_1_4 = ".edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_KAH_2147900778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.KAH!MTB"
        threat_id = "2147900778"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 6f ?? 00 00 0a 13 05 00 07 08 11 05 06 08 06 8e 69 5d 91 59 d1 9d 08 17 58 0c 00 11 04 17 58 13 04 11 04 09 6f ?? 00 00 0a 32 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AB_2147900830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AB!MTB"
        threat_id = "2147900830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 16 5d 91 13 0d 07 11 0b 91 11 08 58 13 0e 11 0c 11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 0a 11 10 11 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RDE_2147901481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RDE!MTB"
        threat_id = "2147901481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "server1" ascii //weight: 1
        $x_1_2 = "Important windows file" ascii //weight: 1
        $x_1_3 = "SoulE Review Switch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RDF_2147902418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RDF!MTB"
        threat_id = "2147902418"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GlobalShortcutCS.Win" ascii //weight: 1
        $x_1_2 = "Bond Technologies" ascii //weight: 1
        $x_1_3 = "AddNewHotKey" ascii //weight: 1
        $x_1_4 = "btnSimulate_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RDG_2147925015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RDG!MTB"
        threat_id = "2147925015"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 10 00 00 0a 13 04 11 04 06 07 6f 11 00 00 0a 13 05 73 01 00 00 0a 13 06 11 06 11 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_RFAK_2147925963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.RFAK!MTB"
        threat_id = "2147925963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 73 49 00 00 0a 0d 00 09 02 16 02 8e 69 6f 4a 00 00 0a 00 09 6f 4b 00 00 0a 00 08 6f 4c 00 00 0a 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_AWIB_2147955937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.AWIB!MTB"
        threat_id = "2147955937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 06 11 1f 6f ?? 00 00 0a 13 20 03 06 6f ?? 00 00 0a 59 13 21 06 12 20 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 21 17 59 25 13 21 16 fe 02 16 fe 01 13 23 11 23 2c 06 00 17 13 07 2b 57 06 12 20 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 21 17 59 25 13 21 16 fe 02 16 fe 01 13 24 11 24 2c 06 00 17 13 07 2b 30 06 12 20 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 1f 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AveMaria_KK_2147960071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AveMaria.KK!MTB"
        threat_id = "2147960071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Path=%TeMp%" ascii //weight: 1
        $x_2_2 = "Setup=bdthgfxtr.cmd" ascii //weight: 2
        $x_3_3 = "Silent=1" ascii //weight: 3
        $x_4_4 = "bdthgfxtr.cmd" ascii //weight: 4
        $x_5_5 = "bzsfvdfv.sfx.exe -d%Temp% -pfnouydzalepdnoioihmyjfodtgfsafdyehofxvflinlnafugyfHbgnmeGRhvqxsd" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

