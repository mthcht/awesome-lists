rule Trojan_MacOS_SuspAmosDownloadAgent_A_2147949643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspAmosDownloadAgent.A"
        threat_id = "2147949643"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspAmosDownloadAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "killall Terminal" ascii //weight: 10
        $x_10_2 = {63 75 72 6c 20 22 68 74 74 70 [0-96] 20 7c 20 6f 73 61 73 63 72 69 70 74}  //weight: 10, accuracy: Low
        $x_10_3 = {63 75 72 6c 20 2d 78 20 70 6f 73 74 20 2d 2d 6d 61 78 2d 74 69 6d 65 [0-96] 2e 7a 69 70}  //weight: 10, accuracy: Low
        $x_10_4 = "osascript -e 'display dialog" ascii //weight: 10
        $x_1_5 = "/dev/null" ascii //weight: 1
        $x_1_6 = "_system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

