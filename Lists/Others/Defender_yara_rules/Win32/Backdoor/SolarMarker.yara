rule Backdoor_Win32_SolarMarker_ARA_2147837911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SolarMarker.ARA!MTB"
        threat_id = "2147837911"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 03 45 f0 89 45 e8 8a 45 f0 8b 55 e8 32 02 32 45 ee 0f b7 55 ee 8b 4d f4 8a 54 11 ff 2a c2 0f b7 55 ee 8b 4d f4 8a 54 11 ff 32 c2 8b 55 e8 88 02 8b 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

