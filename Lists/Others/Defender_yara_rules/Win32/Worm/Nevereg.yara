rule Worm_Win32_Nevereg_AE_2147826272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nevereg.AE!MTB"
        threat_id = "2147826272"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nevereg"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillAV" ascii //weight: 1
        $x_1_2 = "PlutonX" ascii //weight: 1
        $x_1_3 = "xRaKeH" ascii //weight: 1
        $x_1_4 = "VWQSR1" ascii //weight: 1
        $x_1_5 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_6 = "GetDiskFreeSpaceExA" ascii //weight: 1
        $x_1_7 = "PathFileExistsA" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\ed2k" wide //weight: 1
        $x_1_9 = "WINDOWS\\Drivers\\MoviezChannelsInstaler Key Generator.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

