rule Trojan_MSIL_SafetyKatz_ARA_2147919000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SafetyKatz.ARA!MTB"
        threat_id = "2147919000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SafetyKatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii //weight: 2
        $x_2_2 = "SafetyKatz.pdb" ascii //weight: 2
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
        $x_1_4 = "CreateThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

