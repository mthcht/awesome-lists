rule Backdoor_Win64_RogueDaemon_DA_2147968532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RogueDaemon.DA!MTB"
        threat_id = "2147968532"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RogueDaemon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 8b c1 4d 8d 40 01 99 41 ff c1 41 f7 fb 48 63 c2 0f b6 8c 05 20 09 00 00 41 30 48 ff 49 83 ea 01 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

