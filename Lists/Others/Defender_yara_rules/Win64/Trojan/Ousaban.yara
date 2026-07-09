rule Trojan_Win64_Ousaban_GVD_2147973189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ousaban.GVD!MTB"
        threat_id = "2147973189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ousaban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uespemosarenegylmodnarodsetybdet" ascii //weight: 1
        $x_1_2 = "://145.249.109.192/index.php?data" ascii //weight: 1
        $x_1_3 = "://91.92.240.140/1.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

