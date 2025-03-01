rule Trojan_MSIL_Redlinestealer_YKUF_2147822405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redlinestealer.YKUF!MTB"
        threat_id = "2147822405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 25 17 59}  //weight: 1, accuracy: High
        $x_1_2 = {2d 0d 26 16 2d cb 16 fe 02 0c 08 2d d9 2b 03 0b 2b f1 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redlinestealer_UD_2147825448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redlinestealer.UD!MTB"
        threat_id = "2147825448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.ip.sb/ip" ascii //weight: 1
        $x_1_2 = "DecryptBlob" ascii //weight: 1
        $x_1_3 = "BCrbyte[]yptDesbyte[]troyKbyte[]ey" ascii //weight: 1
        $x_1_4 = "FromBase64CharArray" ascii //weight: 1
        $x_1_5 = "get_encrypted_key" ascii //weight: 1
        $x_1_6 = "Roaming\\TReplaceokReplaceenReplaces.tReplacext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redlinestealer_SK_2147900855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redlinestealer.SK!MTB"
        threat_id = "2147900855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 04 06 08 06 09 91 9c 06 09 11 04 9c 08 17 58 0c 08 20 00 01 00 00 3f d1 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = "$d17b41c9-3955-4890-95b8-887aac006e0b" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redlinestealer_SL_2147905076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redlinestealer.SL!MTB"
        threat_id = "2147905076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Leftwards Gran Sensationally" ascii //weight: 2
        $x_2_2 = "Stereo.exe" ascii //weight: 2
        $x_2_3 = "Telegraphically Nil" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

