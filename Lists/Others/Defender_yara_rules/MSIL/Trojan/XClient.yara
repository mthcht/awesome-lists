rule Trojan_MSIL_XClient_A_2147849972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XClient.A!MTB"
        threat_id = "2147849972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XClient"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0b 07 28 ?? 00 00 0a 2c 11 07 73 ?? 00 00 0a 28 ?? 00 00 0a 02 8e 69 6a 2e 07 07 02 28 ?? 00 00 0a 07 28}  //weight: 2, accuracy: Low
        $x_2_2 = "WhitehatDataHM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

