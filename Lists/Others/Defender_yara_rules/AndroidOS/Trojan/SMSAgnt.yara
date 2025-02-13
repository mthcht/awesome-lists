rule Trojan_AndroidOS_SMSAgnt_A_2147834579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSAgnt.A!MTB"
        threat_id = "2147834579"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 00 30 00 13 01 16 00 34 10 4e 00 13 00 c5 00 13 01 61 00 13 02 23 00 71 30 ?? ?? 10 02 0c 00 71 20 ?? ?? 06 00 0a 00 38 00 3e 00 13 00 70 00 13 01 74 00 13 02 1e 00 71 30 ?? ?? 10 02 0c 00 6e 20 ?? ?? 06 00 0c 00 1f 00 9e 00 07 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

