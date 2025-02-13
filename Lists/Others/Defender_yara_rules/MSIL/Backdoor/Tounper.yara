rule Backdoor_MSIL_Tounper_A_2147730580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Tounper.A!MTB"
        threat_id = "2147730580"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tounper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uploading {0} to {1}" wide //weight: 1
        $x_1_2 = "Software\\Yandex\\Punto Switcher\\" wide //weight: 1
        $x_1_3 = "cardnumberhyphens" ascii //weight: 1
        $x_1_4 = "yandexnumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

