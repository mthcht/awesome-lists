rule Trojan_MSIL_Khalesi_NA_2147906171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Khalesi.NA!MTB"
        threat_id = "2147906171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 60 13 00 ?? ?? 17 58 13 03 11 03 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

