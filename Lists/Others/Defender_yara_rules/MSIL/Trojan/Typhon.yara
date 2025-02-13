rule Trojan_MSIL_Typhon_ATY_2147911866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Typhon.ATY!MTB"
        threat_id = "2147911866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Typhon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Typhon.Stealer.Software.VPN" ascii //weight: 1
        $x_1_2 = "Typhon.Stealer.Software.Browsers.Edge" ascii //weight: 1
        $x_1_3 = "7b82d83e-61aa-401e-a104-fecc905df99e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

