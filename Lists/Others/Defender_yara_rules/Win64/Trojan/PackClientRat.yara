rule Trojan_Win64_PackClientRat_AP_2147977545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PackClientRat.AP!MTB"
        threat_id = "2147977545"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PackClientRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 7d 0c 48 89 45 10 48 8d 4d 00 48 8d 85 ?? 02 00 00 66 0f 7f 45 20 0f 57 c9 48 89 45 18 48 89 7d 30 48 89 7d 38 66 0f 7f 45 40 66 0f 7f 4d 50 66 0f 7f 45 60}  //weight: 1, accuracy: Low
        $x_2_2 = {48 89 5d e0 ff 15 ?? ?? ?? ?? 48 8b 4d d0 ff 15 ?? ?? ?? ?? 48 8b 4d d8 ff 15 ?? ?? ?? ?? b9 b8 0b 00 00 ff 15 ?? ?? ?? ?? 4c 8d 85 a0 09 00 00 48 8d 15 2e 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PackClientRat_AK_2147977567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PackClientRat.AK!MTB"
        threat_id = "2147977567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PackClientRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "injection_initialize" ascii //weight: 1
        $x_1_2 = "injection_terminate" ascii //weight: 1
        $x_1_3 = "nvdaHelperRemote.dll" ascii //weight: 1
        $x_1_4 = "NVIDIA Corporation\\NvSvc" ascii //weight: 1
        $x_1_5 = "PACK_LAUNCH_PULL_HOST" ascii //weight: 1
        $x_1_6 = "PACK_LAUNCH_PULL_PORT" ascii //weight: 1
        $x_1_7 = "PACK_LAUNCH_GROUP" ascii //weight: 1
        $x_1_8 = "PackClientLauncherDumps" ascii //weight: 1
        $x_1_9 = "PackClientCore.dll" ascii //weight: 1
        $x_1_10 = "PackMonitorClient\\Plugins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

