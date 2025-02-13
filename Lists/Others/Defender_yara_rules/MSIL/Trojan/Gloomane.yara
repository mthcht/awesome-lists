rule Trojan_MSIL_Gloomane_SK_2147902823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gloomane.SK!MTB"
        threat_id = "2147902823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gloomane"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "44 CALIBER" ascii //weight: 2
        $x_2_2 = "Insidious.exe" ascii //weight: 2
        $x_2_3 = "FuckTheSystem Copyright" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

