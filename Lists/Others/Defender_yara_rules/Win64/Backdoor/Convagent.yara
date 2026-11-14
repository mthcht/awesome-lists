rule Backdoor_Win64_Convagent_KK_2147982108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Convagent.KK!MTB"
        threat_id = "2147982108"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {65 48 8b 0c 25 58 00 00 00 48 8b 04 c1 48 8d b8 01 00 00 00 48 b9 41 71 38 6b 52 32 6d 58 48 89 88 01 00 00 00 66 c7 80 09 00 00 00 70 00 48 8b 46 18 48 8b 4e 20 44 8b 80 08 02 00 00 48 89 fa}  //weight: 20, accuracy: High
        $x_10_2 = "Dark_SessionKey" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

