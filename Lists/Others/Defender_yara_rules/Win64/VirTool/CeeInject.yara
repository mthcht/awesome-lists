rule VirTool_Win64_CeeInject_QW_2147729085_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CeeInject.QW"
        threat_id = "2147729085"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 0f 41 83 e1 03 47 8a 0c 08 44 30 0c 01 48 ff c0 39 d0 41 89 c1 7c ea}  //weight: 1, accuracy: High
        $x_1_2 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CeeInject_BAC_2147730093_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CeeInject.BAC!bit"
        threat_id = "2147730093"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 48 63 d0 48 8b 45 f0 48 8d 1c 02 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 30 48 8b 45 28 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 89 c1 8b 45 fc 99 f7 f9 89 d0 48 63 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 b0 48 8d 1c 02 48 8b 4d e0 e8 e1 fe ff ff 88 03 48 83 45 e0 02 83 45 bc 01 8b 45 bc 3b 45 ac 7c d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

