rule HackTool_Win32_NapiCOFFLoader_A_2147966866_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NapiCOFFLoader.A"
        threat_id = "2147966866"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NapiCOFFLoader"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "napi_register_module_v1" ascii //weight: 2
        $x_1_2 = "BeaconDataParse" ascii //weight: 1
        $x_1_3 = "BeaconDataExtract" ascii //weight: 1
        $x_1_4 = "BeaconDataInt" ascii //weight: 1
        $x_1_5 = "BeaconOutput" ascii //weight: 1
        $x_1_6 = "BeaconPrintf" ascii //weight: 1
        $x_1_7 = "BeaconFormatAlloc" ascii //weight: 1
        $x_1_8 = "BeaconFormatFree" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

