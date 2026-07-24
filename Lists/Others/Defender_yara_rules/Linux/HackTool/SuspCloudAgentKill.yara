rule HackTool_Linux_SuspCloudAgentKill_A_2147974496_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspCloudAgentKill.A"
        threat_id = "2147974496"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspCloudAgentKill"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 73 00 20 00 [0-24] 7c 00 [0-4] 67 00 72 00 65 00 70 00}  //weight: 10, accuracy: Low
        $x_1_2 = "aliyun" wide //weight: 1
        $x_1_3 = "aegis" wide //weight: 1
        $x_1_4 = "YunJing" wide //weight: 1
        $x_1_5 = "BcmServer" wide //weight: 1
        $x_5_6 = {7c 00 20 00 78 00 61 00 72 00 67 00 73 00 20 00 [0-8] 6b 00 69 00 6c 00 6c 00}  //weight: 5, accuracy: Low
        $x_5_7 = {7c 00 78 00 61 00 72 00 67 00 73 00 20 00 [0-8] 6b 00 69 00 6c 00 6c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

