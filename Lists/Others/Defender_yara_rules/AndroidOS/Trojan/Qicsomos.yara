rule Trojan_AndroidOS_Qicsomos_A_2147656218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Qicsomos.A"
        threat_id = "2147656218"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Qicsomos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "projectvoodoo/simplecarrieriqdetector" ascii //weight: 1
        $x_1_2 = "SUSPICIOUS_CLASSES" ascii //weight: 1
        $x_1_3 = "cdma_shadow" ascii //weight: 1
        $x_1_4 = "submitAL34" ascii //weight: 1
        $x_1_5 = "AgentService_J" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

