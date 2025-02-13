rule Backdoor_MacOS_Capip_A_2147752405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Capip.A!MTB"
        threat_id = "2147752405"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Capip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 69 2e [0-32] 2e 63 6f 6d 2f 67 75 61 72 64 69 61 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "Remote script:" ascii //weight: 1
        $x_1_3 = "WARNING: Body is not empty even though request is not POST or PUT. Is this a mistake" ascii //weight: 1
        $x_1_4 = "s8guardian11sendRequest3url6method4body10Foundation4DataVSS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

