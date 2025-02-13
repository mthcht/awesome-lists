rule Trojan_Linux_Meterpreter_B_2147844883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Meterpreter.B!MTB"
        threat_id = "2147844883"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 0c 5e 56 31 1e ad 01 c3 85 c0 75 f7 c3 e8 ef ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Meterpreter_C_2147890020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Meterpreter.C!MTB"
        threat_id = "2147890020"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 c9 48 81 e9 ef ff ff ff 48 8d 05 ef ff ff ff 48 bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

