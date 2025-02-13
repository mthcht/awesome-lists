rule Backdoor_Win32_MsBuildBypass_C_2147814977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/MsBuildBypass.C!dha"
        threat_id = "2147814977"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "MsBuildBypass"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "msbuild.exe" wide //weight: 10
        $x_1_2 = "c:\\windows\\help\\" wide //weight: 1
        $x_1_3 = "c:\\windows\\debug\\" wide //weight: 1
        $x_1_4 = "c:\\windows\\inf\\" wide //weight: 1
        $x_1_5 = "c:\\windows\\media\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

