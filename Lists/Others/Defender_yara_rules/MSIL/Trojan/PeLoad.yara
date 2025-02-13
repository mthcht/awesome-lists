rule Trojan_MSIL_PeLoad_SK_2147899037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PeLoad.SK!MTB"
        threat_id = "2147899037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PeLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunPE\\obj\\Debug\\RunPE.pdb" ascii //weight: 1
        $x_1_2 = "$a872ce1d-166a-4c8a-9ef2-0b7d28c8b2e9" ascii //weight: 1
        $x_1_3 = "RunPE.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

