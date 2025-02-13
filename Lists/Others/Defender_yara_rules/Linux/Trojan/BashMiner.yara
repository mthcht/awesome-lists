rule Trojan_Linux_BashMiner_A_2147807464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BashMiner.A"
        threat_id = "2147807464"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BashMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 7b 6a 6e 64 69 3a 6c 64 61 70 3a 2f 2f 90 02 0f 2f 62 61 73 69 63 2f 63 6f 6d 6d 61 6e 64 2f 62 61 73 65 36 34 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

