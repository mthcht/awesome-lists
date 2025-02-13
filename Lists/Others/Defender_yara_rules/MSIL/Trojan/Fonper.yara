rule Trojan_MSIL_Fonper_A_2147696767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fonper.A"
        threat_id = "2147696767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fonper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyPhoneInfoPeriodicAgent" wide //weight: 1
        $x_1_2 = "MyPhoneInfoResourceIntensiveAgent" wide //weight: 1
        $x_1_3 = "My Phone Info a resource-intensive task." wide //weight: 1
        $x_1_4 = "BNS Error: The action is disabled" wide //weight: 1
        $x_1_5 = "BNS Error: The maximum number of ScheduledActions of this type have already been added." wide //weight: 1
        $x_1_6 = "Firmware revision" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

