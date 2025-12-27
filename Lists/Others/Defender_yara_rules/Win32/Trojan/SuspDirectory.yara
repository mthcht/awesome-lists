rule Trojan_Win32_SuspDirectory_MK_2147955548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDirectory.MK"
        threat_id = "2147955548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDirectory"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "for %G in (.txt)" ascii //weight: 1
        $x_1_3 = "do forfiles /p" ascii //weight: 1
        $x_1_4 = "/s /M *%G /C" ascii //weight: 1
        $x_1_5 = "cmd /c echo @PATH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

