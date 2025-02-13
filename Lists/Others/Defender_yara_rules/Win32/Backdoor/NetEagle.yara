rule Backdoor_Win32_NetEagle_MX_2147758154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetEagle.MX!MTB"
        threat_id = "2147758154"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetEagle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 02 8a 04 02 2a c2 34 ef 8a d8 c0 eb 06 c0 e0 02 0a d8 42 3b 54 24 ?? 88 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

