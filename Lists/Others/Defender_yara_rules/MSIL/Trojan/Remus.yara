rule Trojan_MSIL_Remus_AYA_2147976947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remus.AYA!MTB"
        threat_id = "2147976947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LX_CRYPTER" wide //weight: 5
        $x_2_2 = "payload_package.dat" wide //weight: 2
        $x_1_3 = "LX Protector" wide //weight: 1
        $x_1_4 = "SELECT * FROM SystemLogs" wide //weight: 1
        $x_1_5 = "Biblioteka.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

