rule Trojan_MSIL_BlackNETStealer_DA_2147900292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlackNETStealer.DA!MTB"
        threat_id = "2147900292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackNETStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Anthemia logger" ascii //weight: 1
        $x_1_2 = "PasswordStealer" ascii //weight: 1
        $x_1_3 = "screenshot.png" ascii //weight: 1
        $x_1_4 = "password.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

