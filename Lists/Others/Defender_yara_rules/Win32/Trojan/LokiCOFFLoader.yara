rule Trojan_Win32_LokiCOFFLoader_A_2147966242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiCOFFLoader.A"
        threat_id = "2147966242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiCOFFLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "COFFLoader" ascii //weight: 2
        $x_2_2 = "runCOFF" ascii //weight: 2
        $x_1_3 = "beacon_compatibility" ascii //weight: 1
        $x_1_4 = "go_callback" ascii //weight: 1
        $x_1_5 = "BeaconDataParse" ascii //weight: 1
        $x_1_6 = "BeaconPrintf" ascii //weight: 1
        $x_1_7 = "BeaconOutput" ascii //weight: 1
        $x_1_8 = "BeaconFormatAlloc" ascii //weight: 1
        $x_1_9 = "BeaconFormatFree" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

