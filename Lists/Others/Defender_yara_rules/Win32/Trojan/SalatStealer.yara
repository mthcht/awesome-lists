rule Trojan_Win32_SalatStealer_KAT_2147946544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.KAT!MTB"
        threat_id = "2147946544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decryptData" ascii //weight: 1
        $x_1_2 = "findLsassProcess" ascii //weight: 1
        $x_1_3 = "shellCommand" ascii //weight: 1
        $x_1_4 = "sendScreen" ascii //weight: 1
        $x_1_5 = "runKeylogger" ascii //weight: 1
        $x_1_6 = "salat/main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

