rule Trojan_Win32_Bunitucryt_RM_2147805652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitucryt.RM!MTB"
        threat_id = "2147805652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitucryt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 10 00 00 83 c0 04 3c 00 [0-32] 31 [0-18] 04 [0-18] 04 01 45 ?? 8b [0-5] 3b [0-5] 72 [0-5] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

