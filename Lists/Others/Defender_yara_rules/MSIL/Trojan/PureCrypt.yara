rule Trojan_MSIL_PureCrypt_NEAA_2147841891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypt.NEAA!MTB"
        threat_id = "2147841891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 00 18 5b 11 02 11 00 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 0a 9c 20 04 00 00 00 38 ?? ff ff ff 11 00 11 07 3c ?? ff ff ff 38 ?? ff ff ff 11 07 18 5b}  //weight: 10, accuracy: Low
        $x_2_2 = "QueryResolver" ascii //weight: 2
        $x_2_3 = "Mqoghetk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypt_CCDN_2147895107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypt.CCDN!MTB"
        threat_id = "2147895107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 05 16 6f ?? ?? ?? ?? 13 06 12 06 28 ?? ?? ?? ?? 13 07 11 04 11 07 6f ?? ?? ?? ?? 11 05 17 58 13 05 11 05 09 6f ?? ?? ?? ?? 32 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureCrypt_RR_2147960314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureCrypt.RR!MTB"
        threat_id = "2147960314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 04 28 01 00 00 2b 28 02 00 00 2b 13 05 38 12 00 00 00 11 03 11 04 16 11 02 6f 17 00 00 0a 26 38 db ff ff ff}  //weight: 10, accuracy: High
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = {42 69 74 43 6f 6e 76 65 72 74 65 72 00 54 6f 49 6e 74 33 32}  //weight: 1, accuracy: High
        $x_1_4 = "Trim" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

