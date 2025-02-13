rule Trojan_MSIL_Warzone_SK_2147834676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Warzone.SK!MTB"
        threat_id = "2147834676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Warzone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeysNormalize.g.resources" ascii //weight: 1
        $x_1_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_3 = "GJQJwMrQB" ascii //weight: 1
        $x_1_4 = "KeysNormalize.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

