rule Trojan_AndroidOS_Spymax_N_2147846377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spymax.N!MTB"
        threat_id = "2147846377"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spymax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "package.name.suffix" ascii //weight: 1
        $x_1_2 = "Auto_Click" ascii //weight: 1
        $x_1_3 = "canGoBack" ascii //weight: 1
        $x_1_4 = "wifi_sleep_policy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

