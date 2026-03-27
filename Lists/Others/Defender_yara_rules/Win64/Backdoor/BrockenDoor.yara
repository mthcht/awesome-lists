rule Backdoor_Win64_BrockenDoor_MK_2147965734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BrockenDoor.MK!MTB"
        threat_id = "2147965734"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BrockenDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {4d 8b c8 4c 8b f1 48 89 4d 90 45 33 ff 44 89 7c 24 ?? 41 0f b6 44 10 ff 4c 89 79 10 48 c7 41 ?? 0f 00 00 00 44 88 39 44 8b c0 4c 2b c8 48 83 c2 ?? 49 03 d1 e8}  //weight: 20, accuracy: Low
        $x_15_2 = {49 8b cc 49 3b c4 48 0f 42 c8 48 03 ca 80 39 ?? ?? ?? 48 3b ca ?? ?? 48 ff c9 80 39 ?? ?? ?? 48 2b ca ?? ?? 49 8b cc 66}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

