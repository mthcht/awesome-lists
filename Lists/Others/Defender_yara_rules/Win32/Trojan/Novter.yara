rule Trojan_Win32_Novter_A_2147743836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Novter.A!MSR"
        threat_id = "2147743836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Novter"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7b 22 61 63 63 6c 22 3a 5b 22 [0-5] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 3a [0-3] 2f 22 2c 22 [0-5] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 3a [0-3] 2f 22 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_3 = "killall" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

