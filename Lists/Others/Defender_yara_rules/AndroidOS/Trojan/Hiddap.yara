rule Trojan_AndroidOS_Hiddap_A_2147832216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddap.A!MTB"
        threat_id = "2147832216"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1a 00 00 00 6e 10 ?? ?? 04 00 0c 00 6e 10 ?? ?? 04 00 0c 01 12 02 70 52 ?? ?? 43 10 ?? ?? 6e 10 ?? ?? 04 00 0c 00 6e 10 ?? ?? 04 00 0c 01 12 12 70 52 ?? ?? 43 10 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

