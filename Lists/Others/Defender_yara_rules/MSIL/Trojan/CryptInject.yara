rule Trojan_MSIL_CryptInject_2147729509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject!MTB"
        threat_id = "2147729509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 fe 0c 00 00 20 01 00 00 00 13 04 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 33 0d 20 ?? ?? ?? ?? 13 04 20 ?? ?? ?? ?? 58 00 fe 01 2c 02 2b 05 38 5e ff ff ff 28 ?? 00 00 06 de 08 26 28 ?? 00 00 06 de 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_2147729509_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject!MTB"
        threat_id = "2147729509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 0d 09 13 04 11 04 13 05 11 05 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 06 13 06 11 06 28 ?? 00 00 0a 13 07 11 07 6f ?? 00 00 0a 13 08 11 08 14 14 6f ?? 00 00 0a 26 17 28 ?? 00 00 0a 2b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_2147729509_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject!MTB"
        threat_id = "2147729509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 fe 01 2c 4c 28 ?? 00 00 0a 25 28 ?? 00 00 06 14 fe ?? ?? 00 00 06 73 ?? 00 00 0a 6f ?? 00 00 0a 20 ?? 00 00 00 13 03 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 33 0d 20 ?? ?? 00 00 13 03 20 ?? ?? ?? ?? 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_2147729509_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject!MTB"
        threat_id = "2147729509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 06 28 0c 00 00 06 0c 08 72 1b 00 00 70 28 1a 00 00 0a 39 de 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {11 05 11 06 11 05 11 06 91 1f 1b 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 32 e4}  //weight: 1, accuracy: High
        $x_1_3 = "OSNHlbTWnIoT.resources" wide //weight: 1
        $x_1_4 = "meQTINKP.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_CryptInject_Z_2147731984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.Z"
        threat_id = "2147731984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WizzByPass.pdb" ascii //weight: 1
        $x_1_2 = "WizzByPass.exe" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "CiderMeddeb.Tekri.C4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_CryptInject_RB_2147742469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RB"
        threat_id = "2147742469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 18 5b 1f 10 59 0d 08 1f 20 2f 16 06 08 18 5b 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 2b 1b 07 09 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 06 09 06 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? ?? ?? 0a 32 b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_AR_2147742679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.AR!MTB"
        threat_id = "2147742679"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 1f 0d 28 23 00 00 0a 72 17 02 00 70 28 3e 00 00 0a 0a 02 7b 02 00 00 04 06 17 28 2d 00 00 0a 00 06 73 2e 00 00 0a 0b 07 20 a4 00 00 00 6f 2f 00 00 0a 00 00 de 05}  //weight: 1, accuracy: High
        $x_1_2 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 00 0f 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 00 29 20 00 20 00 40 00 65 00 63 00 68 00 6f 00 20 00 6f 00 66 00 66 00 20 00 26 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 00 29 4a 00 41 00 49 00 53 00 49 00 59 00 41 00 52 00 41 00 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_OJ_2147742846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.OJ!MTB"
        threat_id = "2147742846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 02 8e 69 7e 21 00 00 04 20 ea 00 00 00 7e 21 00 00 04 20 ea 00 00 00 91 03 61 20 b3 00 00 00 5f 9c 32 07 18 0c 38 15 ff ff ff 1d 2b f7 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SV_2147742977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SV!MTB"
        threat_id = "2147742977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 28 4d 00 00 06 02 03 28 15 00 00 06 02 5f 61 d2 2a}  //weight: 1, accuracy: High
        $x_1_2 = {42 7e 02 00 00 04 02 7e 02 00 00 04 8e 69 5d 91 2a}  //weight: 1, accuracy: High
        $x_1_3 = {03 02 7e 02 00 00 04 8e 69 5d 58 2a}  //weight: 1, accuracy: High
        $x_1_4 = {02 04 8f 01 00 00 01 25 47 03 04 28 39 00 00 06 61 d2 52 de 0c}  //weight: 1, accuracy: High
        $x_1_5 = {20 0a 02 00 00 8d 01 00 00 01 25 d0 3a 00 00 04 28 01 00 00 0a 80 3b 00 00 04}  //weight: 1, accuracy: High
        $x_1_6 = {20 9e 01 00 00 8d 05 00 00 01 25 d0 44 00 00 04 28 01 00 00 0a 80 45 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SW_2147742979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SW!MTB"
        threat_id = "2147742979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 03 28 ?? 00 00 06 02 5f 61 d2 2a 30 00 03 28 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {42 7e 02 00 00 04 02 7e 02 00 00 04 8e 69 5d 91 2a}  //weight: 1, accuracy: High
        $x_1_3 = {03 02 7e 02 00 00 04 8e 69 5d 58 2a}  //weight: 1, accuracy: High
        $x_1_4 = {02 04 8f 01 00 00 01 25 47 03 04 28 ?? 00 00 06 61 d2 52}  //weight: 1, accuracy: Low
        $x_1_5 = {02 00 00 8d 01 00 00 01 25 d0 ?? 00 00 04 28 01 00 00 0a 80 ?? 00 00 04 30 00 20 ?? 02 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {01 00 00 8d 05 00 00 01 25 d0 ?? 00 00 04 28 01 00 00 0a 80 ?? 00 00 04 30 00 20 ?? 01 00 00 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RC_2147743032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RC!MSR"
        threat_id = "2147743032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 16 11 05 6f ?? ?? ?? 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RD_2147743033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RD!MSR"
        threat_id = "2147743033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 12 8f 01 70 13 07 72 16 8f 01 70 0c 72 1a 8f 01 70 13 13 72 1e 8f 01 70 13 14 72 16 8f 01 70 13 06 72 8c 8e 01 70 13 12 11 12 72 22 8f 01 70 72 22 8f 01 70 11 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 12 11 12 72 2c 8f 01 70 28 ?? ?? ?? 0a 13 12 11 12 72 30 8f 01 70 72 30 8f 01 70 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 12 11 12 72 3a 8f 01 70 28 ?? ?? ?? 0a 13 12 11 12 72 3e 8f 01 70 28 ?? ?? ?? 0a 13 12 11 12 72 42 8f 01 70 72 42 8f 01 70 11 13 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 12 11 12 72 ee 8e 01 70 28 ?? ?? ?? 0a 13 12 11 12 72 50 8f 01 70 72 50 8f 01 70 11 14 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 12 11 12 72 2c 8f 01 70 28 ?? ?? ?? 0a 13 12 11 12 72 5c 8f 01 70 72 5c 8f 01 70 11 06 28}  //weight: 1, accuracy: Low
        $x_1_2 = {72 2c 8f 01 70 13 19 72 ee 8e 01 70 13 10 72 62 8f 01 70 13 04 72 8c 8e 01 70 13 15 11 15 72 1e 8f 01 70 28 ?? ?? ?? 0a 13 15 11 15 72 66 8f 01 70 72 66 8f 01 70 11 19 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 15 11 15 72 6a 8f 01 70 28 ?? ?? ?? 0a 13 15 11 15 72 6e 8f 01 70 72 6e 8f 01 70 11 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 15 11 15 72 74 8f 01 70 28 ?? ?? ?? 0a 13 15 11 15 72 78 8f 01 70 72 78 8f 01 70 11 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 15 11 0c}  //weight: 1, accuracy: Low
        $x_2_3 = "DVyxEvrx7St77JQX1wkH7MyIQj2iX4+c6Uvr2t4C4jRe6w9MQBLJo1mM3Xthr4FttvM+x/MFW9arZI7Dl9hKwLbzPsfzBVvWq2SOw5fY" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CryptInject_AD_2147743036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.AD!MTB"
        threat_id = "2147743036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 10 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a fe ?? 00 00 fe ?? 00 00 28 ?? 00 00 06 dd ?? 00 00 00 26 dd 00 00 00 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {28 10 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 de ?? 26 de 00 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {7e 0c 00 00 04 28 0f 00 00 06 28 ?? 00 00 0a 28 06 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_CryptInject_AD_2147743036_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.AD!MTB"
        threat_id = "2147743036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 f2 00 00 70 28 ?? 00 00 06 13 05 72 ?? 00 00 70 28 ?? 00 00 06 13 06 72 ?? 00 00 70 28 ?? 00 00 06 13 07 72 ?? 00 00 70 28 ?? 00 00 06 13 08 08 1b 8d ?? 00 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = {1f 49 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 05 1f 45 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 06 1f 41 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 07 1f 3d 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 08 08 1b 8d ?? 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_CryptInject_B_2147743379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.B!MSR"
        threat_id = "2147743379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SmartAssembly.HouseOfCards" ascii //weight: 10
        $x_10_2 = "CreateEncryptor" ascii //weight: 10
        $x_1_3 = "192.3.157.104" ascii //weight: 1
        $x_1_4 = "185.161.209.183" ascii //weight: 1
        $x_1_5 = "185.161.210.111" ascii //weight: 1
        $x_1_6 = "185.157.79.115" ascii //weight: 1
        $x_1_7 = "176.107.177.54" ascii //weight: 1
        $x_1_8 = "193.111.155.137" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CryptInject_SP_2147744238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SP!MTB"
        threat_id = "2147744238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 41 73 70 69 72 65 5c 66 69 6c 65 73 5c [0-64] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RN_2147745241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RN!MSR"
        threat_id = "2147745241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 04 8f 0d 00 00 01 25 47 03 04 28 ?? 00 00 06 61 d2 52 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 06 28 ?? 00 00 06 06 17 58 0a 06 02 8e 69 32 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RT_2147745242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RT!MSR"
        threat_id = "2147745242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 8f 03 00 00 01 25 47 03 06 03 8e 69 5d 91 61 d2 52 06 17 58 0a 06 02 8e 69 32 e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SL_2147745457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SL!MTB"
        threat_id = "2147745457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QWRkSW5Qcm9jZXNzMzIuZXhl" ascii //weight: 1
        $x_1_2 = "UkVWRURVSVZN(VmlydHVhbCBlbnZpcm9ubWVudCBkZXRlY3RlZCE=" ascii //weight: 1
        $x_1_3 = "OlpvbmUuSWRlbnRpZmllcg==" ascii //weight: 1
        $x_1_4 = "U2JpZURsbC5kbGw=" ascii //weight: 1
        $x_1_5 = "ezA6eDJ9(L3RyYmlsZTtjb21wb25lbnQvYWRkb25zLnhhbWw=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_A_2147754278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.A!MTB"
        threat_id = "2147754278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "get_WebServices" ascii //weight: 1
        $x_1_2 = "get_Computer" ascii //weight: 1
        $x_1_3 = "get_User" ascii //weight: 1
        $x_1_4 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_5 = "get_KeySize" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "RegistryKey" ascii //weight: 1
        $x_1_8 = "SetValue" ascii //weight: 1
        $x_1_9 = "CreateSubKey" ascii //weight: 1
        $x_1_10 = {43 3a 5c 55 73 65 72 73 5c 59 65 74 69 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c [0-10] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_11 = "GetProcessesByName" ascii //weight: 1
        $x_1_12 = "Kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_BM_2147755934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.BM!MTB"
        threat_id = "2147755934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\discord\\Local Storage\\leveldb\\" wide //weight: 1
        $x_1_2 = "DiscordHaxx Token Grabber" wide //weight: 1
        $x_1_3 = "https://media.discordapp.net/attachments" wide //weight: 1
        $x_1_4 = "https://wtfismyip.com/text" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_BA_2147756624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.BA"
        threat_id = "2147756624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 45 00 78 00 4d 00 69 00 6e 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "Microsoft Minesweeper Improved" wide //weight: 1
        $x_1_3 = "Atrocity Incorporation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RB_2147758552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RB!MTB"
        threat_id = "2147758552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 1a 58 4a 8f ?? ?? ?? ?? 0c 08 08 47 02 06 1a 58 4a 1f ?? 5d 91 61 d2 52 00 06 1a 58 06 1a 58 4a 17 d6 54 06 1e 58 06 1a 58 4a 06 4a fe ?? 16 fe ?? 52 06 1e 58 46 2d ?? 07 0d 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SF_2147759715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SF!MTB"
        threat_id = "2147759715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e b7 17 da 17 d6 8d ?? 00 00 01 0a 16 02 8e b7 17 da 0d 0c 38 ?? 00 00 00 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 25 fe 0e 04 00 20 ?? 00 00 00 5e 45 ?? 00 00 00 ?? 00 00 00 ?? 00 00 00 ?? 00 00 00 ?? ff ff ff [0-10] 00 00 00 [0-16] 06 08 02 08 91 03 08 03 8e b7 5d 91 61 9c [0-16] 08 17 d6 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {28 1a 00 00 0a 11 0e 11 04 28 d6 00 00 06 6f 1b 00 00 0a 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SF_2147759715_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SF!MTB"
        threat_id = "2147759715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 30 05 00 ba 00 00 00 02 00 00 11 02 8e b7 17 d6 8d 03 00 00 01 0a 16 8c 04 00 00 01 28 02 00 00 0a 26 02 02 8e b7 17 da 91 1f 70 61 0b 28 03 00 00 0a 03 6f 04 00 00 0a 0c 16 8c 04 00 00 01 28 02 00 00 0a 26 16 8c 04 00 00 01 28 02 00 00 0a 26 16 02 8e b7 17 da 0d 13 04 2b 2d 06 11 04 02 11 04 91 07 61 08 11 05 91 61 b4 9c 11 05 03 6f 05 00 00 0a 17 da 33 05 16 13 05 2b 06 11 05 17 d6 13 05 11 04 17 d6 13 04 11 04 09 31 ce 16 8c 04 00 00 01 28 02 00 00 0a 26 06 74 08 00 00 01 02 8e b7 18 da 17 d6 8d 03 00 00 01 28 06 00 00 0a 74 01 00 00 1b 0a 16 8c 04 00 00 01 28 02 00 00 0a 26 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PE_2147761148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PE!MTB"
        threat_id = "2147761148"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$06A56524-4FF3-44E0-9EED-491837735B68" ascii //weight: 1
        $x_1_2 = "sadwqe54qwe5wq7e.Resources.resources" ascii //weight: 1
        $x_1_3 = "1231.12312.1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PF_2147761462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PF!MTB"
        threat_id = "2147761462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 04 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 07 11 04 91 61 d2 81 ?? ?? ?? ?? 02 7b}  //weight: 4, accuracy: Low
        $x_1_2 = {11 04 17 6f [0-6] 11 04 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 08 11 04 91 61 d2 81 ?? ?? ?? ?? 11 04 17 58 13 04 11 04 07 8e 69 32 b2}  //weight: 1, accuracy: Low
        $x_1_3 = {08 11 04 7e ?? ?? ?? ?? 6f [0-6] 11 04 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 08 11 04 91 61 d2 81 ?? ?? ?? ?? 11 04 7e ?? ?? ?? ?? 58 13 04 11 04 07 8e 69 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CryptInject_PF_2147761462_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PF!MTB"
        threat_id = "2147761462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$36623ffc-6c30-4deb-97b5-5876219537a9" ascii //weight: 1
        $x_1_2 = "Patchi" ascii //weight: 1
        $x_1_3 = "Toblerone" ascii //weight: 1
        $x_1_4 = "Cadbury Gifts Direct." ascii //weight: 1
        $x_1_5 = "dbo.Doctors" ascii //weight: 1
        $x_1_6 = "dbo.Patients" ascii //weight: 1
        $x_1_7 = "dbo.Patient_Admissions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PL_2147762584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PL!MTB"
        threat_id = "2147762584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$72308B01-ACAA-4C38-9593-463548C37477" ascii //weight: 1
        $x_1_2 = "Dotnet monopoly easy game" ascii //weight: 1
        $x_1_3 = "DotNetPolyForms.frmSimpleGui.resources" ascii //weight: 1
        $x_1_4 = "DotNetPoly.safasdFSAF.resources" ascii //weight: 1
        $x_1_5 = "MonoGame.Form1.resources" ascii //weight: 1
        $x_1_6 = "Dotnet Poly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PB_2147765443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PB!MTB"
        threat_id = "2147765443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 17 d2 13 34 11 17 1e 63 d1 13 17 11 15 11 09 91 13 28 11 15 11 09 [0-4] 61 ?? ?? ?? 58 61 11 34 61 d2 9c 11 28 13 1f ?? ?? ?? 58 13 09 11 09 11 24 32 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PA_2147765608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PA!MTB"
        threat_id = "2147765608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 15 d2 13 30 11 15 1e 63 d1 13 15 11 1a 11 0b 91 13 26 11 1a 11 0b ?? ?? ?? ?? ?? ?? ?? ?? 58 61 11 30 61 d2 9c 11 26 13 1e ?? ?? ?? 58 13 0b 11 0b 11 27 32 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PA_2147765608_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PA!MTB"
        threat_id = "2147765608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ONLINE_ORDER_SHOPPING_ECOMMERCE_ICON_192431" wide //weight: 1
        $x_1_2 = "adfasdas" ascii //weight: 1
        $x_1_3 = "ResolveSignature" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "get_FullName" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PC_2147765609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PC!MTB"
        threat_id = "2147765609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$a60cc378-b10a-4ff2-803a-56910412b437" ascii //weight: 1
        $x_1_2 = "PlaneGame" ascii //weight: 1
        $x_1_3 = "get_MdiChildren" ascii //weight: 1
        $x_1_4 = "set_MdiParent" ascii //weight: 1
        $x_1_5 = "PlaneParent" ascii //weight: 1
        $x_1_6 = "MDIParent1" ascii //weight: 1
        $x_1_7 = "PlaneGame.MDIParent1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PH_2147765752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PH!MTB"
        threat_id = "2147765752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 40 28 12 00 00 0a 26 16 13 1d 07 6f 13 00 00 0a 0a 12 00 28 10 00 00 0a 13 09 11 09 07 28 14 00 00 0a 13 09 16 13 13 2b 06 11 13 17 58 13 13 11 13 11 09 6f 13 00 00 0a 32 ef}  //weight: 1, accuracy: High
        $x_1_2 = {12 44 28 12 00 00 0a 26 16 13 21 11 05 6f 13 00 00 0a 0a 12 00 28 10 00 00 0a 13 0c 11 07 11 0b 28 14 00 00 0a 13 07 16 13 14 2b 06 11 14 17 58 13 14 11 14 11 07 6f 13 00 00 0a 32 ef}  //weight: 1, accuracy: High
        $x_1_3 = {4c 69 6d 65 5f [0-13] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "VideoLAN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PH_2147765752_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PH!MTB"
        threat_id = "2147765752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\CacheSnort" wide //weight: 1
        $x_1_2 = "https://www.facebook.com/bassam.hesham.mahmoud" wide //weight: 1
        $x_1_3 = "E-Mails : bssam2012@gmail.com, bssam1996@yahoo.com" wide //weight: 1
        $x_1_4 = "\\update\\copier.exe" wide //weight: 1
        $x_1_5 = "https://raw.githubusercontent.com/bssam1996/Copier/master/EXE%20File/Copier.exe" wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\SOFTWARE\\Copier" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_CryptInject_PD_2147765887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PD!MTB"
        threat_id = "2147765887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MACHINE\\Microsoft\\Pay.txt" wide //weight: 1
        $x_1_2 = "Stage2.exe" wide //weight: 1
        $x_1_3 = "ThisIsStage1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PD_2147765887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PD!MTB"
        threat_id = "2147765887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$6d8b6e9f-27b3-41c8-99b3-cadc92773fa0" ascii //weight: 1
        $x_1_2 = "get_MdiChildren" ascii //weight: 1
        $x_1_3 = "set_MdiParent" ascii //weight: 1
        $x_1_4 = "MDIParent1" ascii //weight: 1
        $x_1_5 = "Dama.My" ascii //weight: 1
        $x_1_6 = "Dama.My.Resources" ascii //weight: 1
        $x_1_7 = "Dama.MDIParent1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PM_2147766328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PM!MTB"
        threat_id = "2147766328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 09 47 02 08 1f ?? 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe ?? 16 fe ?? 13 ?? 11 ?? 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PM_2147766328_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PM!MTB"
        threat_id = "2147766328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$f135f12d-4bd6-44fe-a4b4-387c4c358be5" ascii //weight: 2
        $x_2_2 = "CashMe Out" ascii //weight: 2
        $x_2_3 = "CashMeOut.Texas.resources" ascii //weight: 2
        $x_2_4 = "CashMeOut.BlackJackInstructions.resources" ascii //weight: 2
        $x_2_5 = "CashMeOut.SlotsGame.resources" ascii //weight: 2
        $x_2_6 = "CashMeOut.FiveCardDrawHome.resources" ascii //weight: 2
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "Thanks for playing Blackjack!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CryptInject_PG_2147766784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PG!MTB"
        threat_id = "2147766784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 8f 21 00 00 01 25 71 21 00 00 01 07 11 04 91 61 d2 81 21 00 00 01 02 7b ?? 00 00 04 08 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = {08 11 04 8f 21 00 00 01 25 71 21 00 00 01 08 11 04 91 61 d2 81 21 00 00 01 11 04}  //weight: 1, accuracy: High
        $x_1_3 = {58 13 04 11 04 07 8e 69 32 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PI_2147766785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PI!MTB"
        threat_id = "2147766785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_2 = {4c 69 6d 65 5f [0-13] 2e 67 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 69 6d 65 5f [0-13] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "VideoLAN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PJ_2147767362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PJ!MTB"
        threat_id = "2147767362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ssssssssssdssssssss.My" ascii //weight: 1
        $x_1_2 = "dffffffffffffffffffff.dll" ascii //weight: 1
        $x_1_3 = "ddddd.dll" ascii //weight: 1
        $x_1_4 = "ffffffff.dll" ascii //weight: 1
        $x_1_5 = "dfdddddddff.dll" ascii //weight: 1
        $x_1_6 = "ssssssssssdssssssss.Resources.resources" ascii //weight: 1
        $x_1_7 = "$$method0x6000007-1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PK_2147767363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PK!MTB"
        threat_id = "2147767363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "95c69371b9246fe37c3898b7dd200bc1.95c69371b9246fe37c3898b7dd200bc1.Resources.resources" ascii //weight: 10
        $x_10_2 = "CreateDecryptor" ascii //weight: 10
        $x_10_3 = "PublicKeyToken=b03f5f7f11d50a3a" ascii //weight: 10
        $x_2_4 = "8286d0469740a3e495cfff46699c73c40" ascii //weight: 2
        $x_2_5 = "HahaProduction.Properties.Resources" ascii //weight: 2
        $x_1_6 = "CryptoConfig" ascii //weight: 1
        $x_1_7 = "get_CurrentDomain" ascii //weight: 1
        $x_1_8 = "get_IsBrowserHosted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CryptInject_PQ_2147767563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PQ!MTB"
        threat_id = "2147767563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$9367e25f-7abe-4dc8-8b01-954f6473251d" ascii //weight: 1
        $x_1_2 = "WorMS" ascii //weight: 1
        $x_1_3 = "WorMS.frmSupMan.resources" ascii //weight: 1
        $x_1_4 = "WorMS.Resources_icon.png" ascii //weight: 1
        $x_1_5 = "Resource_Stock.dat" ascii //weight: 1
        $x_1_6 = "Resource_Stock_temp.dat" ascii //weight: 1
        $x_1_7 = "butChangeFileDir.Image" ascii //weight: 1
        $x_1_8 = "Remote Desktop Connection" ascii //weight: 1
        $x_1_9 = "WorMS.dlgHomeScreen_ChangeFileDir.resources" ascii //weight: 1
        $x_1_10 = "Are you sure you want to remove the selected resource?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_CryptInject_PR_2147767564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PR!MTB"
        threat_id = "2147767564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$5041fc1e-31ed-499d-bf89-b3fc1142c0f7" ascii //weight: 1
        $x_1_2 = "https://api.coinmarketcap.com/v1/ticker/" ascii //weight: 1
        $x_1_3 = "SimpleTicker" ascii //weight: 1
        $x_1_4 = "Hello! Thank you for trying out WFG!" ascii //weight: 1
        $x_1_5 = "SimpleTickerWindowsForms.SimpleTickerView.resources" ascii //weight: 1
        $x_1_6 = "lblTickerFormatInstructions.Text" ascii //weight: 1
        $x_1_7 = "A simple ticker to display various cryptocurrency prices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PN_2147768390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PN!MTB"
        threat_id = "2147768390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$39959a17-026a-45b9-8cbd-dd5bb0d2981d" ascii //weight: 1
        $x_1_2 = "https://github.com/JulianG97/TextEditor" ascii //weight: 1
        $x_1_3 = "Monopoly.Properties.Resources" ascii //weight: 1
        $x_1_4 = "get_qqqqqqqqqqqqqqqqqqqqqqqqqqqqq" ascii //weight: 1
        $x_1_5 = "A simple windows forms text editor written in C#" ascii //weight: 1
        $x_1_6 = "Monopoly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PO_2147769425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PO!MTB"
        threat_id = "2147769425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$535916f6-ec20-47a3-aa3c-b8710cfd6812" ascii //weight: 1
        $x_1_2 = "Clinic Management System" ascii //weight: 1
        $x_1_3 = "Clinic_Management_System.frm_Patient.resources" ascii //weight: 1
        $x_1_4 = "Clinic_Management_System.MoafaMessageBox.resources" ascii //weight: 1
        $x_1_5 = "Clinic_Management_System.frm_Add_Patient.resources" ascii //weight: 1
        $x_1_6 = "get_qqqqqqqqqqqqqqqqqqqqqqqqqqqqq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PP_2147769426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PP!MTB"
        threat_id = "2147769426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$A2A92227-E7D0-4857-B058-F03AFE4E0BAB" ascii //weight: 1
        $x_1_2 = "EE Mobile Game of the Year" ascii //weight: 1
        $x_1_3 = "Roblox Corporation" ascii //weight: 1
        $x_1_4 = "Roblox.Properties.Resources" ascii //weight: 1
        $x_1_5 = "Cycle_Jump_Game.Form1.resources" ascii //weight: 1
        $x_1_6 = "get_ControlDarkDark" ascii //weight: 1
        $x_1_7 = "Carte chance : La Banque vous doit 5 000 euros." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PT_2147770020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PT!MTB"
        threat_id = "2147770020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$29ff5dca-ae30-47db-b740-8f130aa1b754" ascii //weight: 1
        $x_1_2 = "Token Softwares" ascii //weight: 1
        $x_1_3 = "X3_Profile_Manager.RockPaperScissorsForm.resources" ascii //weight: 1
        $x_1_4 = "X3_Profile_Manager.CoinForm.resources" ascii //weight: 1
        $x_1_5 = "btnToss" ascii //weight: 1
        $x_1_6 = "Rock, Paper, Scissors" ascii //weight: 1
        $x_1_7 = "Que pinga es esto!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PS_2147770165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PS!MTB"
        threat_id = "2147770165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$de99d680-6531-423b-8e5b-a15f9cfffe12" ascii //weight: 1
        $x_1_2 = "Aku Form" ascii //weight: 1
        $x_1_3 = "Aku.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Vendetta Inc." ascii //weight: 1
        $x_1_5 = "Account created, please login!" ascii //weight: 1
        $x_1_6 = "scannedbarcode\":\"" ascii //weight: 1
        $x_1_7 = "Developer: Taravann Heng" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_AMK_2147787251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.AMK!MTB"
        threat_id = "2147787251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fa 25 33 00 16 00 00 02 00 00 00 2c 00 00 00 15 00 00 00 56 00 00 00 6a 00 00 00 3b 00 00 00 0e 00 00 00 01 00 00 00 02}  //weight: 5, accuracy: High
        $x_3_2 = "get_CurrentDomain" ascii //weight: 3
        $x_3_3 = "add_AssemblyResolve" ascii //weight: 3
        $x_3_4 = "ToBase64String" ascii //weight: 3
        $x_3_5 = "OIADNAIS3q" ascii //weight: 3
        $x_3_6 = "GetExecutingAssembly" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_ON_2147794199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.ON!MTB"
        threat_id = "2147794199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHOP_OPEN_ONLINE_STORE_ICON_192439" wide //weight: 1
        $x_1_2 = "adfasdas" ascii //weight: 1
        $x_1_3 = "BitTreeDecoder" ascii //weight: 1
        $x_1_4 = "m_IsRepG0Decoders" ascii //weight: 1
        $x_1_5 = "_solid" ascii //weight: 1
        $x_1_6 = "SetDictionarySize" ascii //weight: 1
        $x_1_7 = "DecodeWithMatchByte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_CK_2147807560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.CK!MTB"
        threat_id = "2147807560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Discord: trx-roblox.com/discord" ascii //weight: 1
        $x_1_2 = "https://pastebin.com/raw/7rXZ9VNc" ascii //weight: 1
        $x_1_3 = "OxygenBytecode.dll" ascii //weight: 1
        $x_1_4 = "PuppyMilkV3.exe" ascii //weight: 1
        $x_1_5 = "AnemoDLL.dll" ascii //weight: 1
        $x_1_6 = "Please send this to helpers on our Discord server!" ascii //weight: 1
        $x_1_7 = "https://discord.gg/trxroblox" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "Please inject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_KA_2147807568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.KA!MTB"
        threat_id = "2147807568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Discord: trx-roblox.com/discord" ascii //weight: 1
        $x_1_2 = "https://pastebin.com/raw/7rXZ9VNc" ascii //weight: 1
        $x_1_3 = "Please inject!" ascii //weight: 1
        $x_1_4 = "PuppyMilkV3.exe" ascii //weight: 1
        $x_1_5 = "AnemoDLL.dll" ascii //weight: 1
        $x_1_6 = "Please send this to helpers on our Discord server!" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "Injecting.." ascii //weight: 1
        $x_1_9 = "DownloadDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_DC_2147816217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.DC!MTB"
        threat_id = "2147816217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Resource viewer, decompiler & recompiler" wide //weight: 1
        $x_1_2 = "ResHack" wide //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "IsCrypted" ascii //weight: 1
        $x_1_6 = "get_IsWorkstation" ascii //weight: 1
        $x_1_7 = "encryptedData" ascii //weight: 1
        $x_1_8 = "ZipAndEncrypt" ascii //weight: 1
        $x_1_9 = "ZipStream" ascii //weight: 1
        $x_1_10 = "NetzStarter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MF_2147816619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MF!MTB"
        threat_id = "2147816619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 16 73 ?? ?? ?? 0a 0b 1a 8d ?? ?? ?? 01 0c 06 06 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 06 08 16 1a 6f ?? ?? ?? 0a 26 08 16 28 ?? ?? ?? 0a 0d 06 16 6a 6f ?? ?? ?? 0a 09 17 da 17 d6 8d ?? ?? ?? 01 13 04 07 11 04 16 09 6f ?? ?? ?? 0a 26 07 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 09}  //weight: 1, accuracy: Low
        $x_1_3 = "ANTIVM" ascii //weight: 1
        $x_1_4 = "Decode" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "ReleaseMutex" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "ReadProcessMemory" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MG_2147818450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MG!MTB"
        threat_id = "2147818450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 02 8e 69 8d ?? ?? ?? 01 0b 16 0c 2b 13 07 08 02 08 91 06 08 06 8e 69 5d 91 61 b4 9c 08 17 d6 0c 08 02 8e 69 32 e7}  //weight: 1, accuracy: Low
        $x_1_2 = "ResumeThread" ascii //weight: 1
        $x_1_3 = "SuspendThread" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "GetTempPath" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MH_2147818452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MH!MTB"
        threat_id = "2147818452"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 13 04 2b 2a 00 07 11 04 9a 6f ?? ?? ?? 0a 03 28 ?? ?? ?? 0a 13 05 11 05 2c 0d 00 07 11 04 9a 6f ?? ?? ?? 0a 0a 2b 14 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 06 11 06 2d c9}  //weight: 1, accuracy: Low
        $x_1_2 = "EasyXploits API" wide //weight: 1
        $x_1_3 = "is injecting" wide //weight: 1
        $x_1_4 = "doShit" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "Did the dll properly inject?" wide //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_N_2147818875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.N!MTB"
        threat_id = "2147818875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 3f b6 1f 09 0f 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 00 01 00 00 20}  //weight: 1, accuracy: High
        $x_1_2 = "Fluxus V7.exe" ascii //weight: 1
        $x_1_3 = "Fluxus_IDE.Properties.Resources.resources" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "\\RobloxPlayerBeta.exe" ascii //weight: 1
        $x_1_6 = "/C Inject.bat" ascii //weight: 1
        $x_1_7 = "\\bin\\Discord.Fluxus" ascii //weight: 1
        $x_1_8 = "DACInject.exe" ascii //weight: 1
        $x_1_9 = "rbxscripts.xyz" ascii //weight: 1
        $x_1_10 = "/FluxusTeamAPI.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NU_2147818958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NU!MTB"
        threat_id = "2147818958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 d5 a2 1f 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 63 00 00 00 82 00 00 00 a9 00 00 00 71 01 00 00 de}  //weight: 1, accuracy: High
        $x_1_2 = "rpkfdsddfsdlevsfdsfveee" ascii //weight: 1
        $x_1_3 = "dddfdffdsdfhfg" ascii //weight: 1
        $x_1_4 = "gsefhfssdlfdsfdsfdfpfdhddgdsg" ascii //weight: 1
        $x_1_5 = "ShortPdddddsdddddddsfsdddddddddrocess Completed" ascii //weight: 1
        $x_1_6 = "ShortdsasdsfsdsProcdess Started" ascii //weight: 1
        $x_1_7 = "ShortPddsaddddddddddddddddddrocess Compfsfleted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_UK_2147819174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.UK!MTB"
        threat_id = "2147819174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShortPfafddddddddddddddddfdddrocess Completed" ascii //weight: 1
        $x_1_2 = "ShortPddddddfddddddddddfdddrocess Completed" ascii //weight: 1
        $x_1_3 = "ShortPddddddddddfmpleted" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NVD_2147819820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NVD!MTB"
        threat_id = "2147819820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 06 08 6f ?? ?? ?? 0a 0b 07 16 73 ?? ?? ?? 0a 13 0b 11 0b 73 ?? ?? ?? 0a 13 04 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {57 1d b6 1d 09 09 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 01 01 00 00 74 00 00 00 cf 00 00 00 6b 02 00 00 62 00 00 00 a1 01 00 00 05 00 00 00 14 00 00 00 1c 00 00 00 01 00 00 00 01 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "LoadLibraryA" ascii //weight: 1
        $x_1_5 = "CreateProcess" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_9 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NP_2147821634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NP!MTB"
        threat_id = "2147821634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k-storage.com/bootstrapper/files/krnl.dll" ascii //weight: 1
        $x_1_2 = "ryos.best/api/update.jit" ascii //weight: 1
        $x_1_3 = {3f b6 1f 09 0b 00 00 00 fa 01 33 00 16 00 00 01}  //weight: 1, accuracy: High
        $x_1_4 = "9aa570077064" ascii //weight: 1
        $x_1_5 = "DownloadDLL" ascii //weight: 1
        $x_1_6 = "GetScriptData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_C_2147821817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.C!MTB"
        threat_id = "2147821817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 5f b6 1f 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "krnlss.krnl_monaco.resources" ascii //weight: 1
        $x_1_3 = "krnlss.exe.config" wide //weight: 1
        $x_1_4 = "Bunifu_UI_v1.5.3.dll" wide //weight: 1
        $x_1_5 = "injector.dll" ascii //weight: 1
        $x_1_6 = "pastebin.com/raw/rT3UCQRs" wide //weight: 1
        $x_1_7 = "krnlss.Games.resource" ascii //weight: 1
        $x_1_8 = "WaitNamedPipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NL_2147822013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NL!MTB"
        threat_id = "2147822013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "faffffgffffff ssssssssssssssss" wide //weight: 1
        $x_1_2 = "dfpddghleted" wide //weight: 1
        $x_1_3 = "Fsdfsdf" wide //weight: 1
        $x_1_4 = "ffsdfsdfds" wide //weight: 1
        $x_1_5 = "FromBase64" ascii //weight: 1
        $x_1_6 = "fdsdfds" wide //weight: 1
        $x_1_7 = "dfdassssssssssdffddleted" wide //weight: 1
        $x_1_8 = {d5 a2 1f 09 0f 00 00 00 fa 25 33 00 16 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NW_2147822438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NW!MTB"
        threat_id = "2147822438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dfdassssssssssdffddleted" ascii //weight: 1
        $x_1_2 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_3 = "hPfdsfhdsdrodscess" ascii //weight: 1
        $x_1_4 = "lpfsdfAfdsddsadress" ascii //weight: 1
        $x_1_5 = "flProdsdtdsfaefdsct" ascii //weight: 1
        $x_1_6 = "fagfdgdas" ascii //weight: 1
        $x_1_7 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_8 = "DynamicDllInvokeType" ascii //weight: 1
        $x_1_9 = "Fsdfsdf" ascii //weight: 1
        $x_1_10 = "ffsdfsdfds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NYZ_2147824730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NYZ!MTB"
        threat_id = "2147824730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 ff a3 3f 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 ce 00 00 00 8b 05 00 00 56 0a 00 00 e0 17 00 00 a3 12 00 00 2a 00 00 00 6d 02 00 00 99 01 00 00 e3 00 00 00 1a 00 00 00 01 00 00 00 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NY_2147826835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NY!MTB"
        threat_id = "2147826835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 20 00 01 00 00 6f ?? ?? ?? 0a 08 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 11 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {3f b6 1f 09 0f 00 00 00 fa 01 33 00 16 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = "4bee-a526-18e06e07de26" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NYH_2147829282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NYH!MTB"
        threat_id = "2147829282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 02 28 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 37 00 00 00 1f 00 00 00 5e 00 00 00 92 00 00 00 31 00 00 00 47 00 00 00 05 00 00 00 09}  //weight: 1, accuracy: High
        $x_1_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resource" ascii //weight: 1
        $x_1_3 = "Plates.dll" ascii //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
        $x_1_5 = "ToArgb" ascii //weight: 1
        $x_1_6 = "BitConverter" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "ToInt32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MI_2147830392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MI!MTB"
        threat_id = "2147830392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0c 06 00 28 1d 00 00 0a 72 aa d7 06 70 28 1e 00 00 0a 6f 1f 00 00 0a 08 28 57 00 00 0a 6f 58 00 00 0a 26 07 17 58 0b 07 73 1c 00 00 0a 1f 0a 1f 14 6f 20 00 00 0a 31 a3}  //weight: 10, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "KillProcessAndChildren" ascii //weight: 1
        $x_1_4 = "remotePort" ascii //weight: 1
        $x_1_5 = "DestroypublicData" ascii //weight: 1
        $x_1_6 = "PostMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_AY_2147832888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.AY!MTB"
        threat_id = "2147832888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 06 02 16 02 8e 69 6f 40 00 00 0a 00 11 06 6f 41 00 00 0a 00 00 de 0d 11 06 2c 08 11 06}  //weight: 5, accuracy: High
        $x_1_2 = "afasfsafsafsafsafasAFSAF" wide //weight: 1
        $x_1_3 = "$6639acc9-0ffa-4664-9bdb-abc453f2be71" ascii //weight: 1
        $x_1_4 = "fsafsafsafas" wide //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NWN_2147835147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NWN!MTB"
        threat_id = "2147835147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 bd a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = "$f554eebb-65bd-4fbe-a912-83b4c10ae54d" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp3.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NZZ_2147837579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NZZ!MTB"
        threat_id = "2147837579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 2b 2b 16 2b 2b 2b 30 2b 35 2b 0b 08 6f ?? 00 00 0a 1b 2c f5 de 0d 09 2b f2}  //weight: 1, accuracy: Low
        $x_1_2 = "Mvzywacd" ascii //weight: 1
        $x_1_3 = "uccfursygylsjm.E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SPQP_2147838118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SPQP!MTB"
        threat_id = "2147838118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {00 07 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 04 11 06 58 47 52 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d7}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NZ_2147838128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NZ!MTB"
        threat_id = "2147838128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$4281b208-39a5-4cc4-b524-6e9af626f621" ascii //weight: 10
        $x_10_2 = "Malaga_game.Properties.Resource" ascii //weight: 10
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
        $x_1_5 = "ColorTranslator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NCI_2147838206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NCI!MTB"
        threat_id = "2147838206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 07 00 00 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 16 20 ?? ?? ?? 00 17 6f ?? ?? ?? 0a 00 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 18 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "JoeRMremoteRelease83" wide //weight: 1
        $x_1_3 = "Joerm.com Customers Remote Assistance Updater" wide //weight: 1
        $x_1_4 = "Joerm.com PCAssistance AutoUpdate" wide //weight: 1
        $x_1_5 = "PCMonitor" wide //weight: 1
        $x_1_6 = "AutoUpdateErrorLog.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBAJ_2147840059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBAJ!MTB"
        threat_id = "2147840059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 08 18 6f ?? 00 00 0a 08 6f 33 00 00 0a 0a 02 13 04 06 11 04 16 11 04 8e b7 6f 34 00 00 0a 0b 07}  //weight: 1, accuracy: Low
        $x_1_2 = {42 51 6c 6d 76 47 42 65 00 00 0d 01 00 08 57 54 70 4d 6b 70 6d 78 00 00 0d 01 00 08 71 49 74 78 59 4d 4b 45}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 49 00 48 00 57 00 37 00 34 00 72 00 6e 00 37 00 50 00 66 00 44 00 7a 00 68 00 68 00 47 00 70 00 59 00 62 00 56 00 6d 00 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_NVA_2147840223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.NVA!MTB"
        threat_id = "2147840223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 bf b6 3f 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 d2 00 00 00 b0 00 00 00 1e 04 00 00 ac 0c 00 00 50 07 00 00 08 00 00 00 11 02 00 00 73 00 00 00 ea 00 00 00 03 00 00 00 18 00 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {57 15 02 1c 09 03 00 00 00 fa 01 33 00 02 00 00 01 00 00 00 53 00 00 00 73 00 00 00 a4 00 00 00 78 01 00 00 cf 01 00 00 a9 00 00 00 04 00 00 00 19 00 00 00 01 00 00 00 04 00 00 00 02 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = {57 b7 a2 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 e3 00 00 00 39 00 00 00 cb 03 00 00 e7 08 00 00 20 05 00 00 09 00 00 00 d4 01 00 00 9e 01 00 00 17 00 00 00 02 00 00 00 80 00 00 00 0a}  //weight: 1, accuracy: High
        $x_1_4 = {57 1f a2 0b 09 0a 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 88 00 00 00 29 00 00 00 bd 00 00 00 80 00 00 00 50 00 00 00 15 00 00 00 dd 00 00 00 09 00 00 00 c9 00 00 00 37 00 00 00 02 00 00 00 05}  //weight: 1, accuracy: High
        $x_1_5 = {57 15 02 1c 09 0a 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 11 00 00 00 03 00 00 00 04 00 00 00 08 00 00 00 01 00 00 00 1c 00 00 00 03 00 00 00 03 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_CryptInject_MBAI_2147840356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBAI!MTB"
        threat_id = "2147840356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 04 11 05 9a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 11 05 17 d6 13 05 11 05 11 07 13 08 11 08 31 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {4a 06 4a 06 28 06 0d 00 33 06 4a 06 0d 00 2e 06 3a 06 0d 00 2e 06 3a 06 0d 00 2d 06 2d 06 0d 00 2e 06 3a 06 0d 00 2e 06 3a 06 0d 00 2e 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBAL_2147840364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBAL!MTB"
        threat_id = "2147840364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lQDfKzMKbn" wide //weight: 1
        $x_1_2 = "4444Config.txt" wide //weight: 1
        $x_1_3 = "0bhOF5ssTd_wewDFI" wide //weight: 1
        $x_1_4 = "Downloads\\ImgName.png" wide //weight: 1
        $x_1_5 = "permunban" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SRP_2147840562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SRP!MTB"
        threat_id = "2147840562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HitlerCircumvent" ascii //weight: 1
        $x_1_2 = "sX/H39qsc2u3+TrgQ2huP/Sw4GP1ooaCHBQgAXVFpPc=" wide //weight: 1
        $x_1_3 = "$$$a$m$s$i$.dll$$$" wide //weight: 1
        $x_1_4 = "$$$Am$si$Sc$an$Buffer$$$" wide //weight: 1
        $x_1_5 = "$$$uFcAB4DD$$$" wide //weight: 1
        $x_1_6 = "$$$CallByName$$$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_AIC_2147842671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.AIC!MTB"
        threat_id = "2147842671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 31 7e bc 01 00 04 06 7e bb 01 00 04 02 07 6f ?? ?? ?? 0a 7e ae 00 00 04 07 7e ae 00 00 04 8e 69 5d 91 61 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBCS_2147843757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBCS!MTB"
        threat_id = "2147843757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 16 08 8e 69 6f ?? 00 00 0a 13 04 11 04 16 31 0c 07 08 16 11 04 6f ?? 00 00 0a 2b e2}  //weight: 1, accuracy: Low
        $x_1_2 = "bbbd-c4bab702618c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBCU_2147843961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBCU!MTB"
        threat_id = "2147843961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 07 09 91 03 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 03 8e 69 32 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MS_2147844804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MS!MTB"
        threat_id = "2147844804"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 06 8e 69 5d 91 0d 07 08 02 08 91 09 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBDG_2147845038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBDG!MTB"
        threat_id = "2147845038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 07 8e 69 8c ?? 00 00 01 14 14 17 8c ?? 00 00 01 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0a 11 0a 11 05 5f 13 0b 07 11 04 8c ?? 00 00 01 07 8e 69 8c ?? 00 00 01 14 14 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_HH_2147845496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.HH!MTB"
        threat_id = "2147845496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 28 11 00 00 06 13 01 38 00 00 00 00 dd 2a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBCI_2147846390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBCI!MTB"
        threat_id = "2147846390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 00 34 00 73 00 49 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 45 00 41 00 4e 00 53 00 39 00 43 00 32 00 78 00 72 00 61 00 33 00 62 00 66 00 39 00 2b 00 6b 00 38}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBCR_2147846569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBCR!MTB"
        threat_id = "2147846569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Syste_m.Refl_ection.As_sembly" wide //weight: 1
        $x_1_2 = "Lo_ad" wide //weight: 1
        $x_1_3 = "Ge_tExp_ortedTy_pes" wide //weight: 1
        $x_1_4 = "Dyn_am_icInv_oke" wide //weight: 1
        $x_1_5 = "Sy_stem.Deleg_ate" wide //weight: 1
        $x_1_6 = "Qjzterhzrb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_UNK_2147847389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.UNK!MTB"
        threat_id = "2147847389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 02 00 00 01 20 00 00 00 00 20 46 7b 70 49 20 27 7b 70 49 61 9d fe 09 03 00 71 02 00 00 01 20 01 00 00 00 20 a6 f5 9f 5f 20 cb f5 9f 5f 61 9d fe 09 03 00 71 02 00 00 01 20 02 00 00 00 20 a2 3d 54 47 20 d1 3d 54 47 61 9d fe 09 03 00 71 02 00 00 01 20 03 00 00 00 20 18 ef 53 05 20 71 ef 53 05 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MKV_2147848004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MKV!MTB"
        threat_id = "2147848004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 5f 07 00 0a 0a dd 20 00 00 00 26 72 3d 00 00 70 72 dc 00 00 70 28 60 07 00 0a 6f 61 07 00 0a 74 27 01 00 01 0a dd 00 00 00 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBEM_2147849454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBEM!MTB"
        threat_id = "2147849454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 10 00 00 8d ?? 00 00 01 13 02 ?? ?? ?? ?? ?? 00 00 73 ?? 00 00 0a 13 03 ?? ?? ?? ?? ?? 00 00 00 11 01 11 02 16 20 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Whoon.Himentater" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBEN_2147849455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBEN!MTB"
        threat_id = "2147849455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 35 00 35 00 46 00 55 00 34 00 36 00 34 00 56 00 48 00 55 00 34 00 38 00 42 00 42 00 55 00 38 00 43 00 53 00 43 00 34 00 48 00 35 00 00 05 68 00 68 00 00 05 67 00 67 00 00 09 4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBET_2147849962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBET!MTB"
        threat_id = "2147849962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 72 36 02 00 70 0d 16 0c 06 07 09 28 ?? 3b 00 06 2d 09 08 17 58 0c 08 1f 64 32 ed}  //weight: 1, accuracy: Low
        $x_1_2 = "DN746552B163" wide //weight: 1
        $x_1_3 = "chromeNotEncode.exe" wide //weight: 1
        $x_1_4 = {77 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 c4 00 01}  //weight: 1, accuracy: High
        $x_1_5 = "ZYXDNGuarder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBEV_2147849963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBEV!MTB"
        threat_id = "2147849963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 28 07 08 09 28 ?? 00 00 0a 16 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 09 11 07 12 03 28 ?? 00 00 0a 2d d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBHZ_2147851803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBHZ!MTB"
        threat_id = "2147851803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e b7 17 da 13 04 0d 2b 2b 08 07 09 9a 28 ?? 00 00 0a 17 6a 61 28 ?? 00 00 0a 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 09 17 d6 0d 09 11 04 31 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PAV_2147888531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PAV!MTB"
        threat_id = "2147888531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 01 13 16 11 16 2c 10 19 45 01 00 00 00 f6 ff ff ff 73 1b 00 00 0a 7a 11 05 11 08 fe 01 13 17 11 17 2c 3a 18 45 01 00 00 00 f6 ff ff ff 00 09 7b 04 00 00 04 11 08 28 ?? ?? ?? 06 25 26 1f 64 28 ?? ?? ?? 06 fe 03 13 18 11 18 2c 10 1a 45 01 00 00 00 f6 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateProcess" ascii //weight: 1
        $x_1_3 = "GetThreadContext" ascii //weight: 1
        $x_1_4 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_5 = "SetThreadContext" ascii //weight: 1
        $x_1_6 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_7 = "ReadProcessMemory" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "UnmapViewOfSection" ascii //weight: 1
        $x_1_10 = "VirtualAllocEx" ascii //weight: 1
        $x_1_11 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PAZ_2147888532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PAZ!MTB"
        threat_id = "2147888532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 11 15 11 04 11 15 91 1f 7a 61 d2 9c 00 11 15 17 58 13 15 11 15 11 04 8e 69 fe 04 13 16 11 16 2d dc}  //weight: 1, accuracy: High
        $x_1_2 = {72 01 00 00 70 7e 0e 00 00 0a 7e 0e 00 00 0a 16 1a 7e 0e 00 00 0a 14 12 05 12 06 28 ?? ?? ?? 06 13 08 16 13 09 11 06 7b 18 00 00 04 13 0a 11 0a 16 12 07 28 ?? ?? ?? 0a 1c 5a 12 09 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBIQ_2147890026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBIQ!MTB"
        threat_id = "2147890026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 00 79 00 00 2d 45 00 38 00 46 00 37 00 44 00 42 00 4a 00 37 00 59 00 42 00 47 00 35 00 47 00 38 00 37 00 46 00 56 00 38 00 31 00 49 00 54 00 5a 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 00 6f 00 64 00 67 00 65 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBJK_2147892183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBJK!MTB"
        threat_id = "2147892183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 6e 00 64 00 69 00 67 00 6f 00 00 01 00 4d 42 00 69}  //weight: 1, accuracy: High
        $x_1_2 = "$de05872a-b88a-499c-b6aa-e215577e5646" ascii //weight: 1
        $x_1_3 = "BitGuard.Compress.Properties.Resources.resource" ascii //weight: 1
        $x_1_4 = "AesManaged" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
        $x_1_6 = "StringSorter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBJM_2147892408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBJM!MTB"
        threat_id = "2147892408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 11 0c 11 0a 6f ?? 00 00 0a 13 0b 11 06 09 19 d8 18 d6 12 0b 28 ?? 00 00 0a 9c 11 06 09 19 d8 17 d6 12 0b 28 ?? 00 00 0a 9c 11 06 09 19 d8 12 0b 28 ?? 00 00 0a 9c 09 17 d6 0d 11 0c 17 d6 13 0c 11 0c 11 0e 31 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {1a 04 29 04 1a 04 39 04 13 04 26 04 16 04 7a 04 43 04 1b 04 41 04 47 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBJS_2147893419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBJS!MTB"
        threat_id = "2147893419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$5B32FFE7-198C-4C8C-BF34-0B9BE8E807EE" ascii //weight: 1
        $x_1_2 = "Sling.dll" ascii //weight: 1
        $x_1_3 = "Sling.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBKS_2147894717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBKS!MTB"
        threat_id = "2147894717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 07 6f ?? 00 00 0a 00 09 04 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 11 04 02 16 02 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {67 00 74 00 73 00 61 00 76 00 6a 00 76 00 45 00 52 00 41 00 63 00 77 00 6b 00 6f 00 47 00 34 00 6d 00 30 00 46 00 68 00 67 00 42 00 53 00 46 00 58 00 5a 00 66 00 66 00 6d 00 42 00 4b 00 49 00 73 00 6b 00 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBKS_2147894717_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBKS!MTB"
        threat_id = "2147894717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 00 56 00 4e 00 4a 00 5e 00 41 00 44 00 5e 00 5e 00 41 00 5f 00 5e 00 5e 00 41 00 50 00 37 00 37 00 59 00 5e 00 43 00 34 00 5e 00 5e 00 5e 00 5e 00 5e 00 41 00 43 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 4c 00 75 00 75 00 4e 00 69 00 65 00 6d 00 2e 00 43 00 6f 00 75 00 70 00 6f 00 6e 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBEH_2147895193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBEH!MTB"
        threat_id = "2147895193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 65 00 77 00 7a 00 72 00 62 00 76 00 76 00 6c 00 61 00 6c 00 72 00 6b 00 2e 00 53 00 66 00 79 00 64 00 6d 00 74 00 2e 00 64 00 6c 00 6c 00 00 17 51 00 76 00 67 00 65 00 77 00 6d 00 64 00 65 00 73 00 63 00 73}  //weight: 1, accuracy: High
        $x_1_2 = "Tewzrbvvlalrk.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "$10f705ae-7326-484f-8fdc-64e92feb60fd" ascii //weight: 1
        $x_1_4 = "ConsoleApp13.exe" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBEO_2147895691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBEO!MTB"
        threat_id = "2147895691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fghhfgsfffdddshfdasdfh" ascii //weight: 1
        $x_1_2 = "sgfhjffgdrhdfdhffadfsfsscfdb" ascii //weight: 1
        $x_1_3 = "djfffafcfdssfkfhgj" ascii //weight: 1
        $x_1_4 = "ffchkfdafhfj" ascii //weight: 1
        $x_1_5 = "sgfjhjffgrfhddfhffadfsfsscfgdb" ascii //weight: 1
        $x_1_6 = "hdffhhfhdggfhdfdfhdjfhdasffffkdf" ascii //weight: 1
        $x_1_7 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PA22_2147899469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PA22!MTB"
        threat_id = "2147899469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {17 2d 06 d0 41 00 00 06 26 7e 11 00 00 04 02 91 0a 02 17 58 fe 0b 00 00 38 7c 00 00 00 7e 11 00 00 04 02 91 1f 40 5f 2d 2f 1d 45 01 00 00 00 f6 ff ff ff 7e 11 00 00 04 02 91 20 7f ff ff ff 5f 1e 62 0a 06 7e 11 00 00 04 02 17 58 91 60 0a 02 18 58 fe 0b 00 00 2b 41 7e 11 00 00 04 02 91 20 3f ff ff ff 5f 1f 18 62 0a 06 7e 11 00 00 04 02 17 58 91 1f 10 62 60 0a 06 7e 11 00 00 04 02 18 58 91 1e 62 60 0a 06 7e 11 00 00 04 02 19 58 91 60 0a 02 1a 58 fe 0b 00 00 06 17 2f 10}  //weight: 5, accuracy: High
        $x_1_2 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_3 = "SFZwT0wk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBFU_2147902585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBFU!MTB"
        threat_id = "2147902585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 06 08 06 6f ?? 00 00 0a 1f ?? 61 d2 9c 06 17 58 0a 06 08 6f ?? 00 00 0a 32 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_XC_2147903117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.XC!MTB"
        threat_id = "2147903117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualProtect" ascii //weight: 1
        $x_1_2 = "Decrypt" ascii //weight: 1
        $x_1_3 = "Decompress" ascii //weight: 1
        $x_1_4 = "ReverseDecode" ascii //weight: 1
        $x_1_5 = "CopyBlock" ascii //weight: 1
        $x_1_6 = "WriteInt64" ascii //weight: 1
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" wide //weight: 1
        $x_1_9 = "BitDecoder" ascii //weight: 1
        $x_1_10 = "BitTreeDecoder" ascii //weight: 1
        $x_1_11 = "DecodeDirectBits" ascii //weight: 1
        $x_1_12 = "LzmaDecoder" ascii //weight: 1
        $x_1_13 = "m_IsMatchDecoders" ascii //weight: 1
        $x_1_14 = {43 6f 70 79 42 6c 6f 63 6b 00 50 75 74 42 79 74 65 00 47 65 74 42 79 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBZV_2147906786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBZV!MTB"
        threat_id = "2147906786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 69 67 71 79 64 76 78 74 00 3c 4d 6f 64 75 6c 65 3e 00 49 6e 66 6f 49 6e 76 6f 63 61 74 69 6f 6e 44 65 66 00 41 69 67 71 79 64 76 78 74}  //weight: 10, accuracy: High
        $x_1_2 = "Qtlnyyqhiol.Annotations" ascii //weight: 1
        $x_1_3 = "ZipAndAes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBYC_2147908018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBYC!MTB"
        threat_id = "2147908018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 03 06 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 06 17 58 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "vMeJL4ytO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_SPMP_2147910505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.SPMP!MTB"
        threat_id = "2147910505"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {06 18 d8 0a 06 1f 18 fe 02 0c 08 2c 03 1f 18 0a 06 1f 18 5d 16 fe 03 0d 09 2d e5}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_PDF_2147912046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.PDF!MTB"
        threat_id = "2147912046"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 6f 00 00 06 26 11 06 1f 0b 93 20 6a 29 00 00 59 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_YR_2147913202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.YR!MTB"
        threat_id = "2147913202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 02 7b 04 00 00 04 8e 69 5d 0c 06 07 03 07 91 02 7b 04 00 00 04 08 91 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHE_2147913372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHE!MTB"
        threat_id = "2147913372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "goudieelectric.shop" wide //weight: 1
        $x_1_2 = "DownloadData" wide //weight: 1
        $x_1_3 = "wsc_proxy" wide //weight: 1
        $x_1_4 = "get_CurrentThread" ascii //weight: 1
        $x_1_5 = "get_IsAttached" ascii //weight: 1
        $x_1_6 = "Debugger" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
        $x_1_8 = "op_Explicit" ascii //weight: 1
        $x_2_9 = {2e 72 65 6c 6f 63 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 65 78 74}  //weight: 2, accuracy: Low
        $x_2_10 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? fe 37}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBYW_2147913902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBYW!MTB"
        threat_id = "2147913902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 4b 00 75 00 45 00 74 00 36 00 6d 00 6d 00 2f 00 30 00 4d 00 70 00 2b 00 4a 00 2b 00 65 00 6e 00 5a 00 4a 00 34 00 67 00 72 00 47 00 33 00 72 00 77 00 4e 00 65 00 64 00 48 00 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHK_2147914305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHK!MTB"
        threat_id = "2147914305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 9e 0b 00 00 18 00 00 00 00 00 00 ce bd}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 00 01 00 1a 20 00 00 00 00 00 00 a8 0d 00 00 01 00}  //weight: 2, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "kernel32.dll" ascii //weight: 1
        $x_1_5 = "sender" ascii //weight: 1
        $x_1_6 = "OpenFile" ascii //weight: 1
        $x_1_7 = "Form1_Load" ascii //weight: 1
        $x_1_8 = "nameOfCust" ascii //weight: 1
        $x_1_9 = "Episode" ascii //weight: 1
        $x_1_10 = "XPS Printing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHL_2147914306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHL!MTB"
        threat_id = "2147914306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "insight.defenseinsight.in" wide //weight: 1
        $x_1_2 = "compname" wide //weight: 1
        $x_1_3 = "webcam" wide //weight: 1
        $x_1_4 = "shellexec" wide //weight: 1
        $x_1_5 = "screen" wide //weight: 1
        $x_2_6 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 ?? ?? ?? 00 00 00 08}  //weight: 2, accuracy: Low
        $x_1_7 = "EncryptOutput" ascii //weight: 1
        $x_1_8 = "GetHostName" ascii //weight: 1
        $x_1_9 = "IPAddress" ascii //weight: 1
        $x_1_10 = "Decompress" ascii //weight: 1
        $x_1_11 = "toHost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHO_2147916625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHO!MTB"
        threat_id = "2147916625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 6c 1e 00 00 08 00 00 00 00 00 00 4e 8a 1e}  //weight: 2, accuracy: Low
        $x_2_2 = "SSEN1b9v2dMZBDmClNgH" ascii //weight: 2
        $x_1_3 = "Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = {6a 00 73 00 00 1d 2f 00 43 00 20 00 63 00 6f 00 70 00 79 00 20 00 2a 00 2e 00 6a 00 73}  //weight: 1, accuracy: High
        $x_1_5 = "System.Data.Linq.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBXL_2147917649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBXL!MTB"
        threat_id = "2147917649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2c 61 02 17 9a 12 00 28 52 01 00 0a 2c 55 02 18 9a}  //weight: 2, accuracy: High
        $x_2_2 = {57 bf a2 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01}  //weight: 2, accuracy: High
        $x_1_3 = "CreateDecryptor" wide //weight: 1
        $x_1_4 = "RijndaelManaged" wide //weight: 1
        $x_1_5 = "System.Security.Cryptography.DESCryptoServiceProvider" wide //weight: 1
        $x_1_6 = "TRM.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHP_2147918300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHP!MTB"
        threat_id = "2147918300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0b 00 00 ?? 03 00 00 16 00 00 00 00 00 00 ?? ?? 03}  //weight: 2, accuracy: Low
        $x_2_2 = {48 6f 69 00 47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d}  //weight: 2, accuracy: High
        $x_2_3 = {6f 70 5f 45 71 75 61 6c 69 74 79 00 e2 80}  //weight: 2, accuracy: High
        $x_1_4 = "server1.exe" wide //weight: 1
        $x_1_5 = "Important display driver" wide //weight: 1
        $x_2_6 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHQ_2147918334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHQ!MTB"
        threat_id = "2147918334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0b 00 00 f0 49 00 00 a0 01 00 00 00 00 00 fe 0d 4a}  //weight: 2, accuracy: Low
        $x_1_2 = "file:" wide //weight: 1
        $x_1_3 = "Location" wide //weight: 1
        $x_1_4 = "ResourceA" wide //weight: 1
        $x_1_5 = "Write" wide //weight: 1
        $x_1_6 = "Process" wide //weight: 1
        $x_1_7 = "Memory" wide //weight: 1
        $x_1_8 = "Close" wide //weight: 1
        $x_1_9 = "Handle" wide //weight: 1
        $x_1_10 = "kernel" wide //weight: 1
        $x_1_11 = "32.dll" wide //weight: 1
        $x_1_12 = "Debugger Detected" wide //weight: 1
        $x_1_13 = "clientMutexId" ascii //weight: 1
        $x_2_14 = {a8 25 00 00 04 00 80 80 00 00 01 00 20 00 28 08 01 00 05 00 00 00 00 00 01 00 20 00 be 52}  //weight: 2, accuracy: High
        $x_1_15 = "newsoftgnu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CryptInject_MBXT_2147921635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBXT!MTB"
        threat_id = "2147921635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {46 53 43 56 4c 41 42 41 51 47 48 55 47 57 55 00 41 42 56 50 53 4c 48 4e 4a}  //weight: 3, accuracy: High
        $x_2_2 = {74 43 54 36 42 30 77 36 61 00 63 48 38 49 58 63 77}  //weight: 2, accuracy: High
        $x_1_3 = "BotClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBXU_2147921636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBXU!MTB"
        threat_id = "2147921636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {38 38 61 64 32 66 64 37 63 65 37 61 61 66 38 37 62 62 62 37 38 31 00 63 61 66 30 33 63 62 36 35 63 32 37 35 63 38}  //weight: 2, accuracy: High
        $x_2_2 = {32 38 30 33 66 66 39 62 34 33 61 35 36 65 37 36 35 35 00 63 37 63 66 31 30 61 62 38 64 64 33 62 36 65 30 39 65}  //weight: 2, accuracy: High
        $x_1_3 = "ProDRENALIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CryptInject_RHAK_2147924166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHAK!MTB"
        threat_id = "2147924166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 08 00 00 52 03 00 00 08 00 00 00 00 00 00 fe 70 03}  //weight: 2, accuracy: Low
        $x_3_2 = "rubberpartsmanufacturers.com/hunziq/Eodnuiwio.mp4" wide //weight: 3
        $x_2_3 = "Zmkwrra.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBWA_2147926103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBWA!MTB"
        threat_id = "2147926103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? 00 00 0a 59 0b}  //weight: 2, accuracy: Low
        $x_1_2 = "2154a4eea3ff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHAM_2147926139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHAM!MTB"
        threat_id = "2147926139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "smithpropertysolutions.com/Crypto.exe" wide //weight: 3
        $x_2_2 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 0a 00 00 00 08 00 00 00 00 00 00 5a 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_TEH_2147927126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.TEH!MTB"
        threat_id = "2147927126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 12 03 28 55 00 00 0a 73 80 00 00 0a 13 04 20 20 00 00 02 28 ec 03 00 06 28 6a 00 00 0a 6f 6b 00 00 0a 72 54 4e 00 70 6f 62 00 00 0a 73 7f 00 00 0a 25 6f 7a 00 00 0a 16 6a 6f 63 00 00 0a 25 25 6f 7a 00 00 0a 6f 64 00 00 0a 69 6f 81 00 00 0a 13 05}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHAO_2147928028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHAO!MTB"
        threat_id = "2147928028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "No-Love" wide //weight: 3
        $x_1_2 = "cmd.exe" wide //weight: 1
        $x_1_3 = "/c ping 0 -n 2 & del" wide //weight: 1
        $x_1_4 = "SystemDrive" wide //weight: 1
        $x_1_5 = "Software\\" wide //weight: 1
        $x_1_6 = "BS.exe" wide //weight: 1
        $x_1_7 = "\\BS.pdb" ascii //weight: 1
        $x_2_8 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 50 00 00 26 00 00 00 08 00 00 00 00 00 00 d2 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RHAP_2147929408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RHAP!MTB"
        threat_id = "2147929408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "github.com/olosha1/oparik/raw/refs/heads/main/gjawedrtg.exe" wide //weight: 3
        $x_2_2 = "-NoProfile" wide //weight: 2
        $x_2_3 = "-ExecutionPolicy Bypass -Command" wide //weight: 2
        $x_1_4 = "powershell.exe" wide //weight: 1
        $x_2_5 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_RH_2147934370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.RH!MTB"
        threat_id = "2147934370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "/DARJ.mp3up%" ascii //weight: 3
        $x_2_2 = "2I3-4-5" wide //weight: 2
        $x_1_3 = "ENEZEZfFFdx" ascii //weight: 1
        $x_1_4 = "/KARK NEW.mp3PK" ascii //weight: 1
        $x_1_5 = "/Gata_Qudri_02.mp3PK" ascii //weight: 1
        $x_2_6 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 08 00 00 bc 13 00 00 6e d1 00 00 00 00 00 ae da 13}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBS_2147934979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBS!MTB"
        threat_id = "2147934979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 2b 76 03 02 61 20 00 01 00 00 28 ?? 00 00 06 59 06 61}  //weight: 2, accuracy: Low
        $x_1_2 = "Larewibifa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_MBT_2147934980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.MBT!MTB"
        threat_id = "2147934980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 05 12 05 28 55 00 00 0a 2d 41 02 17 25 0a 7d 14 00 00 04 02 11 05 7d 18 00 00 04 02 7c 15 00 00 04 12 05 02}  //weight: 2, accuracy: High
        $x_1_2 = {65 00 73 00 73 00 2e 00 74 00 78 00 74 00 00 51 67 00 68 00 70 00 5f 00 51 00 4e 00 38 00 6e 00 5a 00 58 00 56 00 79 00 57 00 33 00 77 00 64 00 41 00 4a 00 6d 00 79 00 59 00 54 00 7a 00 76 00 64 00 31 00 69 00 79 00 78 00 35 00 57 00 75 00 35 00 30 00 32 00 4a 00 7a 00 6c 00 56 00 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_BSA_2147935496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.BSA!MTB"
        threat_id = "2147935496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 9d a2 1d 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 37 00 00 00 12 00}  //weight: 10, accuracy: High
        $x_10_2 = "Hallaj.Properties" ascii //weight: 10
        $x_9_3 = "lover.exe" ascii //weight: 9
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_BSA_2147935496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.BSA!MTB"
        threat_id = "2147935496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_13_1 = {41 6d 65 63 64 2e 65 78 65 00 41 6d 65 63 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 6f 75 73 65 4f 66 43}  //weight: 13, accuracy: Low
        $x_10_2 = "2b73c51c-9d53-4a40-8269-a53478fa16d4" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_BSA_2147935496_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.BSA!MTB"
        threat_id = "2147935496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d0 3b 00 00 01 2b 17 7e 71 00 00 04 20 56 c0 66 06 2b 12 2b 17 2b 1c 2b 1d 2b 22 2b 27 2a}  //weight: 10, accuracy: High
        $x_10_2 = {2b e2 02 2b e1 28 43 00 00 0a 2b dc 28 01 00 00 2b 2b d7 6f 45 00 00 0a 2b d2}  //weight: 10, accuracy: High
        $x_9_3 = "MemberRefsProxy" ascii //weight: 9
        $x_9_4 = "SmartAssembly.HouseOfCards" ascii //weight: 9
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_BSA_2147935496_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.BSA!MTB"
        threat_id = "2147935496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 17 01 00 70 28 05 00 00 0a 6f 09 00 00 0a}  //weight: 5, accuracy: High
        $x_5_2 = {72 83 01 00 70 28 05 00 00 0a 6f 09 00 00 0a 80 1e 00 00 04}  //weight: 5, accuracy: High
        $x_3_3 = {08 07 17 73 22 00 00 0a 0d 09 02 16 02 8e 69 6f 23 00 00 0a}  //weight: 3, accuracy: High
        $x_2_4 = {09 2c 06 09 6f 26 00 00 0a dc 08 2c 06 08 6f}  //weight: 2, accuracy: High
        $x_2_5 = "V293NjRTZXRUaHJlYWRDb250ZXh0" ascii //weight: 2
        $x_2_6 = "U2V0VGhyZWFkQ29udGV4dA==" ascii //weight: 2
        $x_2_7 = "VmlydHVhbEFsbG9jRXg" ascii //weight: 2
        $x_2_8 = "WndVbm1hcFZpZXdPZ1N1Y3Rpb24=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_DAA_2147936284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.DAA!MTB"
        threat_id = "2147936284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 09 02 09 6f 2a 00 00 0a 03 09 07 5d 6f 2a 00 00 0a 61 d1 9d 09 17 58 0d 09 06 32 e3}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_DAB_2147940151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.DAB!MTB"
        threat_id = "2147940151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1a 8d 05 00 00 01 0c 07 08 16 1a 6f 0d 00 00 0a 26 08 16 28 0e 00 00 0a 26 07 16 73 0f 00 00 0a 0d 09 06 6f 10 00 00 0a 06 6f 0a 00 00 0a 13 04 dd 27}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptInject_JYAA_2147941511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptInject.JYAA!MTB"
        threat_id = "2147941511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 08 66 0c 08 17 58 0c 08 66 0c 08 07 61 0c}  //weight: 2, accuracy: High
        $x_2_2 = {06 07 17 58 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

