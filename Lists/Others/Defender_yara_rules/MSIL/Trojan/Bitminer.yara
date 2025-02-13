rule Trojan_MSIL_Bitminer_GP_2147853232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bitminer.GP!MTB"
        threat_id = "2147853232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bitminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://plus-ccmcleanerprog.ru/nvrtc64_112_0.dll" wide //weight: 1
        $x_1_2 = "https://plus-ccmcleanerprog.ru/nvrtc-builtins64_112.dll" wide //weight: 1
        $x_1_3 = "https://plus-ccmcleanerprog.ru/ddb64.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

