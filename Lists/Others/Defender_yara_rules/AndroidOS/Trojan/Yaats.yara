rule Trojan_AndroidOS_Yaats_A_2147848036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Yaats.A"
        threat_id = "2147848036"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Yaats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TickTick Received" ascii //weight: 2
        $x_2_2 = "services/ClientSignalRService" ascii //weight: 2
        $x_2_3 = "ui/NuF6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

