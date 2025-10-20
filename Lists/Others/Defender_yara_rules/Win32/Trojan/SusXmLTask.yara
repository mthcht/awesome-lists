rule Trojan_Win32_SusXmLTask_A_2147955627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusXmLTask.A"
        threat_id = "2147955627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusXmLTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" ascii //weight: 1
        $x_1_2 = "/create /TN" ascii //weight: 1
        $x_1_3 = "Events\\CacheTask_test" wide //weight: 1
        $x_1_4 = "/XML" ascii //weight: 1
        $x_1_5 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_6 = "events.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusXmLTask_B_2147955628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusXmLTask.B"
        threat_id = "2147955628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusXmLTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c dir" ascii //weight: 1
        $x_1_2 = "mkdir" ascii //weight: 1
        $x_1_3 = "AppData\\Local" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusXmLTask_C_2147955629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusXmLTask.C"
        threat_id = "2147955629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusXmLTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create" ascii //weight: 1
        $x_1_2 = "/sc minute /mo" ascii //weight: 1
        $x_1_3 = "AppData\\Local" ascii //weight: 1
        $x_1_4 = "Maintenance" ascii //weight: 1
        $x_1_5 = "/tn" wide //weight: 1
        $x_1_6 = ".vbs" wide //weight: 1
        $x_1_7 = "/tr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

