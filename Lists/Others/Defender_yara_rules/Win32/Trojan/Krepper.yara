rule Trojan_Win32_Krepper_AJ_2147601778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krepper.AJ"
        threat_id = "2147601778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krepper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "240"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Melkosoft Corporation" wide //weight: 100
        $x_100_2 = "http://win-eto.com/hp.htm" ascii //weight: 100
        $x_10_3 = "HookProc" ascii //weight: 10
        $x_10_4 = "Cassandra" ascii //weight: 10
        $x_10_5 = "AppInit_DLLs" ascii //weight: 10
        $x_10_6 = "UnhookWindowsHookEx" ascii //weight: 10
        $x_1_7 = "5F43E716-596C-4fb8-B11B-4D268F3CDAFA-V34" ascii //weight: 1
        $x_1_8 = "4E74E0EF-D424-4012-BCCD-1097C5CB6FC7-V34" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

