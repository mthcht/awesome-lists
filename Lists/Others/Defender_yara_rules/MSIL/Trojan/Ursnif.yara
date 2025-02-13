rule Trojan_MSIL_Ursnif_RB_2147842524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursnif.RB!MTB"
        threat_id = "2147842524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 26 00 03 74 ?? ?? ?? ?? 72 ?? ?? ?? ?? 20 ?? ?? ?? ?? 14 14 14 6f ?? ?? ?? ?? 2c 02 de 0e de 03 26 de 00 06 17 58 0a 06 1f 0a 32 d5 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ursnif_MBEG_2147848928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ursnif.MBEG!MTB"
        threat_id = "2147848928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hfsdkfdhghffshsfegfdafffdch" ascii //weight: 1
        $x_1_2 = "fhhfgdffrfffdkdfadhfghfdasdfh" ascii //weight: 1
        $x_1_3 = "fsgfrgfafddhdffffkhsjd" ascii //weight: 1
        $x_1_4 = "sddddfffheghdfdjffffgjhsdgsfaafcsafp" ascii //weight: 1
        $x_1_5 = "shsdshdsd" ascii //weight: 1
        $x_1_6 = "sfhjffkfhgfdjsrfhdfdfhfffadsgfahsscffgdb" ascii //weight: 1
        $x_1_7 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

