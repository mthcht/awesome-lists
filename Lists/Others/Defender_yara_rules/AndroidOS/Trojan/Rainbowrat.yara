rule Trojan_AndroidOS_Rainbowrat_A_2147892073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rainbowrat.A"
        threat_id = "2147892073"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rainbowrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$microphoneRecordFile" ascii //weight: 1
        $x_1_2 = "WxBcm15AknsdklASkDS2139jScno3FNd39nvo9wn39ascn3o9nKDnF9efnDFNOFDj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rainbowrat_B_2147962224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rainbowrat.B!MTB"
        threat_id = "2147962224"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rainbowrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/RainbowHandler/RainbowCommendHandler" ascii //weight: 1
        $x_1_2 = "/RainbowHandler/RainbowKeyloggerHandler" ascii //weight: 1
        $x_1_3 = "/RainbowNetwork/RainbowUpload" ascii //weight: 1
        $x_1_4 = "RainbowFileExploreHandler" ascii //weight: 1
        $x_1_5 = "getOnKeylogger" ascii //weight: 1
        $x_1_6 = "getOutgoingSmsList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

