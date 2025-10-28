rule Backdoor_Linux_ZynorRAT_A_2147956175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/ZynorRAT.A!MTB"
        threat_id = "2147956175"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "ZynorRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.handleShellCommand" ascii //weight: 1
        $x_1_2 = "main.handlePersistence" ascii //weight: 1
        $x_1_3 = "main.sendDocument" ascii //weight: 1
        $x_1_4 = "main.handleScreenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

