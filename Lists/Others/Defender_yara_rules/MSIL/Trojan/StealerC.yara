rule Trojan_MSIL_StealerC_CXII_2147852429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.CXII!MTB"
        threat_id = "2147852429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 0d 38 1d 00 00 00 00 08 07 09 07 8e 69 5d 91 02 09 91 61 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 00 09 17 58 0d 09 02 8e 69 fe 04 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerC_SPQN_2147897591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.SPQN!MTB"
        threat_id = "2147897591"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 05 16 16 6f ?? ?? ?? 06 16 31 01 2a 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 11 07 17 58 13 07 11 07 1b 32 cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerC_NE_2147905686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.NE!MTB"
        threat_id = "2147905686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0c 11 07 58 11 09 59 93 61 11 0b ?? 2c 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerC_MBZV_2147906787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.MBZV!MTB"
        threat_id = "2147906787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 06 07 93 20 ?? ?? ?? 00 61 02 61 d1 9d}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 41 00 64 00 78 00 57 00 00 47 62 00 61 00 62 00 65 00 6c}  //weight: 1, accuracy: High
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Aigqydvxt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerC_EC_2147907693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.EC!MTB"
        threat_id = "2147907693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://pz.wyjsq.cn/steamspeedAESpz.bin" ascii //weight: 1
        $x_1_2 = "http://pz.wyjsq.cn/gxrz.txt" ascii //weight: 1
        $x_1_3 = "lpkj139498" ascii //weight: 1
        $x_1_4 = "=steamstorecommunitysite" ascii //weight: 1
        $x_1_5 = "=steamLivevideoaddress" ascii //weight: 1
        $x_1_6 = "=steamstartclient" ascii //weight: 1
        $x_1_7 = "=steamothersite" ascii //weight: 1
        $x_1_8 = "=githubsite" ascii //weight: 1
        $x_1_9 = "=uplaysite" ascii //weight: 1
        $x_1_10 = "C:\\Windows\\System32\\drivers\\etc\\hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerC_AMAG_2147919408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.AMAG!MTB"
        threat_id = "2147919408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 ?? 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 91 61 d2 81 ?? 00 00 01 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerC_AMAG_2147919408_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.AMAG!MTB"
        threat_id = "2147919408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JprCj82eY1e7mjrGxw.d1oAiYIBYaO9D2A9cZ" ascii //weight: 2
        $x_1_2 = "w5RWfKgbEirtaOLWRW.F1P6iqSIZ6HrtAgnwr" ascii //weight: 1
        $x_1_3 = "AF1gaDhOOhOdbLwMjqt6" ascii //weight: 1
        $x_1_4 = "bxKJoJNoGNGLTKQN99" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerC_CZ_2147920290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerC.CZ!MTB"
        threat_id = "2147920290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cH8IXcwQY4Peh2qpAn" ascii //weight: 2
        $x_2_2 = "xrUtBVoaXtCT6B0w6a" ascii //weight: 2
        $x_2_3 = "vJiGl01UUJfXfNWas3" ascii //weight: 2
        $x_1_4 = "DyyVDbaRvM1YfIq9il" ascii //weight: 1
        $x_1_5 = "KX0HrYNeb" ascii //weight: 1
        $x_1_6 = "StrReverse" ascii //weight: 1
        $x_1_7 = "CLBYNAMEOXYAODSDFFFG4HHTTRYYUII5OOPPLJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

