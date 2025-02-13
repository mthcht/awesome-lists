rule TrojanDropper_Win32_DCRat_SK_2147755319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/DCRat.SK!MTB"
        threat_id = "2147755319"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Rename]" ascii //weight: 1
        $x_1_2 = "%s%s.dll" ascii //weight: 1
        $x_1_3 = "C:\\TEMP\\dal.exe" ascii //weight: 1
        $x_1_4 = "\\mnb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

