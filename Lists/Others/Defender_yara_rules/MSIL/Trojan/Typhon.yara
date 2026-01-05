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

rule Trojan_MSIL_Typhon_PVA_2147960499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Typhon.PVA!MTB"
        threat_id = "2147960499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Typhon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 1a 11 1a 1f 10 64 d1 13 15 11 15 d2 13 37 11 15 1e 63 d1 13 15 11 20 11 09 91 13 22 11 20 11 09 11 22 11 2a 61 19 11 1e 58 61 11 37 61 d2 9c 11 09 17 58 13 09 11 22 13 1e 11 09}  //weight: 5, accuracy: High
        $x_2_2 = {11 2b 11 12 11 16 11 12 91 9d 17 11 12 58 13 12 11 12 11 0c 32 ea 11 2b}  //weight: 2, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

