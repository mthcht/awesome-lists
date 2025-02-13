rule Trojan_AndroidOS_Xolco_B_2147902890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Xolco.B!MTB"
        threat_id = "2147902890"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Xolco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUI_SCAN_FINISH" ascii //weight: 1
        $x_1_2 = "STOP_CONNECT_CONNECT_SERVER_FAIL" ascii //weight: 1
        $x_1_3 = "SW_PRODUCT_HANDWATE_REV" ascii //weight: 1
        $x_1_4 = "mUpdateHttpClient.downFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

