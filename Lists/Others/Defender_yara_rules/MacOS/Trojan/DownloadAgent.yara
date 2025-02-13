rule Trojan_MacOS_DownloadAgent_A_2147901200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/DownloadAgent.A"
        threat_id = "2147901200"
        type = "Trojan"
        platform = "MacOS: "
        family = "DownloadAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 75 64 6f 20 69 6e 73 74 61 6c 6c 65 72 20 2d 70 6b 67 20 2f 74 6d 70 2f 70 79 74 68 6f 6e [0-32] 2e 70 6b 67 20 2d 74 61 72 67 65 74 [0-32] 3c 3f 78 6d 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "subprocess.call(['killall', 'NotificationCenter'])" ascii //weight: 1
        $x_1_3 = "spctl --master-disable" ascii //weight: 1
        $x_1_4 = {69 6d 6f 00 6a 61 6e 65 00 66 65 65 64 00 76 6f 61 00 64 61 61 69 6c 79 00 72 6f 6e 67 00 61 70 70 00 6e 65 77 73 00 68 75 62}  //weight: 1, accuracy: High
        $x_1_5 = {25 40 2e 25 73 25 73 2e 6e 65 74 [0-32] 54 68 65 20 68 61 73 68 65 73 20 61 72 65 20 74 68 65 20 73 61 6d 65 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

