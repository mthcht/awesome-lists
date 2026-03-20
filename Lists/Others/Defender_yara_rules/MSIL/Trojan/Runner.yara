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

rule Trojan_MSIL_Runner_GPSG_2147965284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Runner.GPSG!MTB"
        threat_id = "2147965284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PSAiN2EwOTI5NjE0OUFkNzU3NDVkODA1Q0ZjNGNlMjE1NTczYjQ0" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

