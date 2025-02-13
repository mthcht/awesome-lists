rule Trojan_Win64_BugSleepLoader_ABL_2147923975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BugSleepLoader.ABL!MTB"
        threat_id = "2147923975"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BugSleepLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b f0 f2 0f 11 44 24 20 80 44 24 20 fb 80 44 24 21 fb 80 44 24 22 fb 80 44 24 23 fb 80 44 24 24 fb 80 44 24 25 fb 80 44 24 26 fb 80 44 24 27 fb 66 89 4c 24 28 0f b6 0d ?? ?? ?? ?? 80 44 24 28 fb 80 44 24 29 fb 88 4c 24 2a 48 8b ce 41 ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

