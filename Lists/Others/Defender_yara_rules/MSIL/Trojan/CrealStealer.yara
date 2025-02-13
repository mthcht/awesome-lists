rule Trojan_MSIL_CrealStealer_AABK_2147849180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrealStealer.AABK!MTB"
        threat_id = "2147849180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrealStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b63bd186-94d1-4557-921e-31c443d48f84" ascii //weight: 1
        $x_1_2 = "GalaxySwapperv2.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

