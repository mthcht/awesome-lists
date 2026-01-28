rule Backdoor_Win64_AdaptixC2_MK_2147961854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AdaptixC2.MK!MTB"
        threat_id = "2147961854"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptixC2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {48 83 ec 10 89 4d 10 c7 ?? ?? ?? ?? ?? ?? 8b 45 10 89 45 f8 48 8d 45 fc 0f b6 00 3c dd 75 37 48 8d 45 f8 0f b6 55 13 88 10 48 8d 45 f8 48 83 c0 01 0f b6 55 12 88 10 48 8d 45 f8 48 83 c0 02}  //weight: 25, accuracy: Low
        $x_15_2 = {83 c0 02 89 c2 b8 ab aa aa aa 48 0f af c2 48 c1 e8 20 d1 e8 c1 e0 02 83 c0 01 89 45 fc 8b 45 fc 48 89 c2 b9 40}  //weight: 15, accuracy: High
        $x_10_3 = "cmd.exe /c start \"\" /B %s" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

