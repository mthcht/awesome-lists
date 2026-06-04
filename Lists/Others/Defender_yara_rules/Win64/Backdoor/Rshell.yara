rule Backdoor_Win64_Rshell_MK_2147970907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Rshell.MK!MTB"
        threat_id = "2147970907"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Rshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_35_1 = {48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 0f b6 0d ?? ?? ?? ?? 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01}  //weight: 35, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

