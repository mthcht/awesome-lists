rule Trojan_MSIL_Apost_EM_2147895590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Apost.EM!MTB"
        threat_id = "2147895590"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Apost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "charmhost.pdb" ascii //weight: 1
        $x_1_2 = "__payload" ascii //weight: 1
        $x_1_3 = "IsAdministrator" ascii //weight: 1
        $x_1_4 = "RemoveLuckyCharm" ascii //weight: 1
        $x_1_5 = "VMEntry" ascii //weight: 1
        $x_1_6 = "EtherShieldVM.Runtime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Apost_NBL_2147896415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Apost.NBL!MTB"
        threat_id = "2147896415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Apost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 53 84 3b cf 66 20 3c 28 ce 10 59 20 97 54 f6 1f 61 20 de 01 aa 19 20 10 2e 73 fa 61 20 bc d4 e7 04 58 20 83 04 c1 e8 61 20 15 bc 90 df 20 bd 33 48 1d 58 65 20 24 10 27 03 59 1f d2 17 63 65 20 26 02 01 fd 20 e2 fd fe 02 58 20 80 00 00 00 1d 63 65 66}  //weight: 1, accuracy: High
        $x_1_2 = "Invoke" ascii //weight: 1
        $x_1_3 = "C NONA.exe" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "set_Key" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Apost_NS_2147931769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Apost.NS!MTB"
        threat_id = "2147931769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Apost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {20 c0 0f 00 00 28 06 00 00 0a 00 14 fe 06 03 00 00 06 73 07 00 00 0a 28 08 00 00 0a}  //weight: 3, accuracy: High
        $x_2_2 = {72 01 00 00 70 0a 28 ?? 00 00 0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 0c 07 72 ?? 00 00 70 28 ?? 00 00 0a 0d 14 13 04 12 05 fe 15 03 00 00 02 12 06 fe 15 04 00 00 02 73 ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

