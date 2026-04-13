rule Trojan_Win32_LokiCOFFLoaderDLL_A_2147966865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiCOFFLoaderDLL.A"
        threat_id = "2147966865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiCOFFLoaderDLL"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "napi_register_module_v1" ascii //weight: 2
        $x_2_2 = "runCOFF" ascii //weight: 2
        $x_1_3 = "beacon_compatibility" ascii //weight: 1
        $x_1_4 = "go_callback" ascii //weight: 1
        $x_1_5 = "BeaconDataParse" ascii //weight: 1
        $x_1_6 = "BeaconDataInt" ascii //weight: 1
        $x_1_7 = "BeaconPrintf" ascii //weight: 1
        $x_1_8 = "BeaconOutput" ascii //weight: 1
        $x_1_9 = "BeaconFormatAlloc" ascii //weight: 1
        $x_1_10 = "BeaconFormatFree" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

