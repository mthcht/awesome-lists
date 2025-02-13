rule Trojan_MSIL_Runner_GP_2147896642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Runner.GP!MTB"
        threat_id = "2147896642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {47 69 20 ad 00 00 00 61 9d 11 0e}  //weight: 2, accuracy: High
        $x_2_2 = {47 69 1f 44 61 9d 11 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

