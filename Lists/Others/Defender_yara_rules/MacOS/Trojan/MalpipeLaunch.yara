rule Trojan_MacOS_MalpipeLaunch_A_2147975101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MalpipeLaunch.A!MTB"
        threat_id = "2147975101"
        type = "Trojan"
        platform = "MacOS: "
        family = "MalpipeLaunch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "| osascript" wide //weight: 1
        $x_1_2 = "curl " wide //weight: 1
        $x_1_3 = {78 00 20 00 70 00 6f 00 73 00 74 00 20 00 68 00 74 00 74 00 70 00 [0-60] 20 00 2d 00 64 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

