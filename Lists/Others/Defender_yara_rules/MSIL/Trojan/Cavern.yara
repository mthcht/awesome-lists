rule Trojan_MSIL_Cavern_GVA_2147974521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cavern.GVA!MTB"
        threat_id = "2147974521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cavern"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://auth.hospitalinstallation.com" wide //weight: 1
        $x_1_2 = "send_;;_" wide //weight: 1
        $x_1_3 = "SkipVerification" ascii //weight: 1
        $x_1_4 = "id.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

