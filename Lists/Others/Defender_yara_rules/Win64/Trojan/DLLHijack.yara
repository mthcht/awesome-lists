rule Trojan_Win64_DLLHijack_EC_2147923737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.EC!MTB"
        threat_id = "2147923737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 08 48 8d 40 01 80 c1 4b 80 f1 3f 80 e9 4b 88 48 ff 48 83 ea 01 75 e7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

