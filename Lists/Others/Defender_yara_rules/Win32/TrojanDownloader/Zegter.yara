rule TrojanDownloader_Win32_Zegter_SK_2147837950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zegter.SK!MTB"
        threat_id = "2147837950"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://47.93.60.63:8000/exploror.exe" ascii //weight: 1
        $x_1_2 = "C:\\windowss64\\computer.exe" ascii //weight: 1
        $x_1_3 = "md C:\\windowss64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

