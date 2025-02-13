rule Trojan_MSIL_Lazysteal_MBZT_2147905949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazysteal.MBZT!MTB"
        threat_id = "2147905949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazysteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 94 58 20 00 01 00 00 5d 94 0a 02 07 02 07 91 06 28 ?? ?? ?? 0a 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

