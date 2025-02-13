rule TrojanSpy_Win32_MassLogger_MB_2147764056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/MassLogger.MB!MTB"
        threat_id = "2147764056"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 18 80 f3 ?? 8b fa 03 fe 88 1f 8b da 03 de 80 33 ?? 46 40 49 75 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

