rule Trojan_AndroidOS_AndroScan_A_2147793492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AndroScan.A!MTB"
        threat_id = "2147793492"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AndroScan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "androscan.net/install.php" ascii //weight: 1
        $x_1_2 = {6d 65 73 73 61 67 65 20 74 6f 20 61 6c 6c 20 6f 66 20 74 68 65 20 64 65 76 69 63 65 e2 80 99 73 20 63 6f 6e 74 61 63 74 73}  //weight: 1, accuracy: High
        $x_1_3 = "spy on the SMS" ascii //weight: 1
        $x_1_4 = "MALWARESDB" ascii //weight: 1
        $x_1_5 = "SMS trojan" ascii //weight: 1
        $x_1_6 = "send SMS messages" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

