rule Trojan_Win32_ToneShell_EC_2147923829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ToneShell.EC!MTB"
        threat_id = "2147923829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ToneShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/C schtasks /F /Create /TN FFWallpaperEmbCore /SC minute /MO 6 /TR \"C:\\ProgramData\\FFWallpaperCore\\SFFWallpaperCore.exe" ascii //weight: 3
        $x_1_2 = "ZackAllen......techyteachme Ok" ascii //weight: 1
        $x_1_3 = "Start...buitengebieden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

