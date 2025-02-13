rule Trojan_Linux_Disgomoji_A_2147923941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Disgomoji.A!MTB"
        threat_id = "2147923941"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Disgomoji"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadAndSendToOshi" ascii //weight: 1
        $x_1_2 = "main.createCronJob" ascii //weight: 1
        $x_1_3 = "main.zipFirefoxProfile" ascii //weight: 1
        $x_1_4 = "downloadFileFromURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

