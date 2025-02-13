rule Backdoor_Win32_Pigeon_GMX_2147896985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pigeon.GMX!MTB"
        threat_id = "2147896985"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pigeon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {18 2a 40 00 00 63 40 00 d8 29 40 00 40 2a 40 00 04 63 40 00 d8 29 40 00 58 2a 40 00 08 63 40 00 d8 29 40 00}  //weight: 10, accuracy: High
        $x_1_2 = "56q.5d6d.com" ascii //weight: 1
        $x_1_3 = "\\dnfahk.ahk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

