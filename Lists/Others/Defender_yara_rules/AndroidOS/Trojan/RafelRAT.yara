rule Trojan_AndroidOS_RafelRAT_A_2147922772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RafelRAT.A!MTB"
        threat_id = "2147922772"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RafelRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 23 1e 00 46 04 01 03 6e 10 fc bb 04 00 0a 05 38 05 0d 00 6e 10 04 bc 04 00 0c 05 6e 20 25 94 56 00 6e 10 f3 bb 04 00 28 04 6e 10 f3 bb 04 00 d8 03 03 01 28 e6}  //weight: 1, accuracy: High
        $x_1_2 = "Victim Connected : ID" ascii //weight: 1
        $x_1_3 = "Rafel-Rat-" ascii //weight: 1
        $x_1_4 = "Your files have been encripted" ascii //weight: 1
        $x_1_5 = "rehber_oku" ascii //weight: 1
        $x_1_6 = "swagkarnaloveshandeercel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

