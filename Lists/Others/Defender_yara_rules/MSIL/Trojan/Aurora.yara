rule Trojan_MSIL_Aurora_ABTJ_2147846395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Aurora.ABTJ!MTB"
        threat_id = "2147846395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aurora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 01 00 00 70 06 16 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 72 f6 11 00 70 06 07 28 ?? 00 00 0a 0c 08 72 1c 12 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0d 72 0f 00 00 70 13 04 02 2c 23 02 8e 69 17 33 1d}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetScriptBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

