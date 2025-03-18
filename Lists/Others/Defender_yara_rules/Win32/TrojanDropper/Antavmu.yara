rule TrojanDropper_Win32_Antavmu_EASX_2147936244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Antavmu.EASX!MTB"
        threat_id = "2147936244"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Antavmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 64 24 00 8a 14 38 80 ea 7a 80 f2 19 88 14 38 40 3b c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

