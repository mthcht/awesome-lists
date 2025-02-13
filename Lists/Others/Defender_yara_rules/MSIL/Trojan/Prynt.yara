rule Trojan_MSIL_Prynt_DDVF_2147828296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Prynt.DDVF!MTB"
        threat_id = "2147828296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Prynt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 9a 16 9a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2d 11 06 08 9a 16 9a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 2b 05 28 ?? ?? ?? 0a 06 08 9a 17 9a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0d 09 07 06 08 9a 18 9a 6f 1e 00 00 0a 74 02 00 00 1b 28 ?? ?? ?? 06 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

