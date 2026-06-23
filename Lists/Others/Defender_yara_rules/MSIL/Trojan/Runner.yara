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

rule Trojan_MSIL_Runner_SX_2147970477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Runner.SX!MTB"
        threat_id = "2147970477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {09 28 0c 00 00 0a a2 11 04 17 16 8c 0c 00 00 01 a2 11 04 18 16 8c 0d 00 00 01 a2 11 04 6f 0d 00 00 0a 26 07 28 0e 00 00 0a 26}  //weight: 30, accuracy: High
        $x_10_2 = "$env:MSEDGE_SKIP_UAC='1';IEX(gc '" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Runner_SXA_2147972119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Runner.SXA!MTB"
        threat_id = "2147972119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {18 5a 16 28 ?? 00 00 0a 11 ?? 17 58 13 ?? 11 ?? 11 ?? 6f ?? 00 00 0a 32 e3}  //weight: 30, accuracy: Low
        $x_20_2 = {69 32 dc 73 ?? 00 00 0a 13 ?? 11 ?? 73 ?? 00 00 0a 13 ?? 11 ?? 16 73 ?? 00 00 0a 13 ?? 11 ?? 11 ?? 6f ?? 00 00 0a 11 ?? 6f ?? 00 00 0a 13 ?? de 0c}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

