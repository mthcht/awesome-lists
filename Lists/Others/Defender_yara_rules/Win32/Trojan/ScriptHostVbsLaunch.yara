rule Trojan_Win32_ScriptHostVbsLaunch_A_2147981692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScriptHostVbsLaunch.A"
        threat_id = "2147981692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScriptHostVbsLaunch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "//nologo" wide //weight: 1
        $x_1_3 = "exec-glob.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

