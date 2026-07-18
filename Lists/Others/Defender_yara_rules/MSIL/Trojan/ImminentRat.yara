rule Trojan_MSIL_ImminentRat_ANXB_2147973579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ImminentRat.ANXB!MTB"
        threat_id = "2147973579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ImminentRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 06 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

