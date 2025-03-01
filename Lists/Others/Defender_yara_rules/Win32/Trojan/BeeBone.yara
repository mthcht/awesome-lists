rule Trojan_Win32_BeeBone_RPM_2147837013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BeeBone.RPM!MTB"
        threat_id = "2147837013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BeeBone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pastebin.com/raw/u8q9u5eD" wide //weight: 1
        $x_1_2 = "filedn.eu/lTR6RKkuGUMReko6LXMbs00/TAB.txt" wide //weight: 1
        $x_1_3 = "taskkill.exe /f /t /im chrome.exe" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = "bit.ly/3OOgjws" wide //weight: 1
        $x_1_6 = "\\svchost.exe" wide //weight: 1
        $x_1_7 = "\\endz.bat" wide //weight: 1
        $x_1_8 = "SCHTASKS /DELETE /TN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

