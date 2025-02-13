rule Trojan_AndroidOS_Meds_A_2147832430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Meds.A!MTB"
        threat_id = "2147832430"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Meds"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 02 00 01 13 03 7a 00 36 32 f9 ff 49 02 00 01 13 03 61 00 34 32 f3 ff 49 02 00 01 d8 02 02 9f 8e 22 50 02 00 01 49 02 00 01 d8 02 02 1a d8 02 02 f6 dc 02 02 1a 8e 22 50 02 00 01 49 02 00 01 d8 02 02 61 8e 22 50 02 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

