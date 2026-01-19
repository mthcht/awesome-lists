rule Ransom_MSIL_LimeCrypt_PA_2147961316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LimeCrypt.PA!MTB"
        threat_id = "2147961316"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".Lime" wide //weight: 3
        $x_1_2 = "/c netsh advfirewall firewall add rule name=\"LimeRAT\" dir=in action=allow program=" wide //weight: 1
        $x_1_3 = "All your files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

