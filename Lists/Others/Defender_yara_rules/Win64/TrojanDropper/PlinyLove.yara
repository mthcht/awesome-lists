rule TrojanDropper_Win64_PlinyLove_VGK_2147968461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/PlinyLove.VGK!MTB"
        threat_id = "2147968461"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "PlinyLove"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.createMaliciousExtension" ascii //weight: 1
        $x_1_2 = "main.killChrome" ascii //weight: 1
        $x_1_3 = "main.loadExtensionInChrome" ascii //weight: 1
        $x_1_4 = "main.addToStartup" ascii //weight: 1
        $x_1_5 = "C:/PlinyDropper/" ascii //weight: 1
        $x_1_6 = "-s -w -H=windowsgui" ascii //weight: 1
        $x_1_7 = "Pliny Love" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

