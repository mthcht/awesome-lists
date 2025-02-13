rule PUA_Win32_FlashHelper_288802_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/FlashHelper"
        threat_id = "288802"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "FlashHelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FlashHelper TaskMachineCore 2th" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\miniconfig" wide //weight: 1
        $x_1_3 = "mini.ffnews.cn" wide //weight: 1
        $x_1_4 = "next_open_interval" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

