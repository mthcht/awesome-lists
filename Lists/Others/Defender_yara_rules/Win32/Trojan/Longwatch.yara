rule Trojan_Win32_Longwatch_2147741465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Longwatch!MTB"
        threat_id = "2147741465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Longwatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\temp\\log.txt" ascii //weight: 1
        $x_1_2 = "------CLIPBOARD----" ascii //weight: 1
        $x_1_3 = "[ENTER]" ascii //weight: 1
        $x_1_4 = "[PRINT SCREEN]" ascii //weight: 1
        $x_1_5 = "[SLEEP]" ascii //weight: 1
        $x_1_6 = "[CapsLock]" ascii //weight: 1
        $x_1_7 = "[PAGE_UP]" ascii //weight: 1
        $x_1_8 = "[LEFT]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

