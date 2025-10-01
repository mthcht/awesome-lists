rule Trojan_MSIL_Mintluks_AMI_2147953776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mintluks.AMI!MTB"
        threat_id = "2147953776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mintluks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 13 06 13 04 2b 1e 07 09 11 04 9a 02 1b 6f ?? 00 00 06 03 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 11 04 17 d6 13 04 11 04 11 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

