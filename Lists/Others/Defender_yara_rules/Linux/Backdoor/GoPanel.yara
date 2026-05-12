rule Backdoor_Linux_GoPanel_DA_2147969055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GoPanel.DA!MTB"
        threat_id = "2147969055"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GoPanel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.sendTelegram" ascii //weight: 1
        $x_1_2 = "main.changeRootPassword" ascii //weight: 1
        $x_1_3 = "main.injectLoginPage" ascii //weight: 1
        $x_1_4 = "main.updateCpanel" ascii //weight: 1
        $x_1_5 = "main.selfDelete" ascii //weight: 1
        $x_1_6 = "main.getMySQLPassword" ascii //weight: 1
        $x_1_7 = "main.postData" ascii //weight: 1
        $x_1_8 = "main.setFileOwner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

