rule Backdoor_Win32_Spyder_C_2147967446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spyder.C!MTB"
        threat_id = "2147967446"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 04 3e 88 04 0e 46 3b 35 ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

