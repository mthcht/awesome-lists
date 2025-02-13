rule PUA_Win32_FusionCore_C_266656_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/FusionCore.C"
        threat_id = "266656"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "FusionCore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FUS_SHOWOFFERS" ascii //weight: 1
        $x_1_2 = "FUS_INITDLL" ascii //weight: 1
        $x_1_3 = "FUS_DECLINEOFFER" ascii //weight: 1
        $x_1_4 = "FUS_GETDLLSTATE" ascii //weight: 1
        $x_1_5 = "FUS_NEXTOFFER" ascii //weight: 1
        $x_1_6 = "FUS_INSTALLOFFERS" ascii //weight: 1
        $x_1_7 = "FUS_FREEDLL" ascii //weight: 1
        $x_1_8 = "FUS_OFFER_DEFAULT_CAPTION" ascii //weight: 1
        $x_1_9 = "FUS_OFFER_DESC" ascii //weight: 1
        $x_1_10 = "FUS_OFFER_CAPTION_PREFIX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

