rule Backdoor_Win32_Touasper_A_2147649961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Touasper.A"
        threat_id = "2147649961"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Touasper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {f1 03 00 00 7c dd 46 39 7d fc 72 34}  //weight: 3, accuracy: High
        $x_1_2 = "VRLDownloadToCacheFileA" ascii //weight: 1
        $x_1_3 = "!b=z&7?cc,MQ>" ascii //weight: 1
        $x_1_4 = "superhard corp." wide //weight: 1
        $x_1_5 = "DreateRemoteThread" ascii //weight: 1
        $x_1_6 = "Computer name:  %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Touasper_B_2147655452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Touasper.B"
        threat_id = "2147655452"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Touasper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PID=%d, ParentPID=%d, PriorityClass=%d, Threads=%d, Heaps=%d" ascii //weight: 1
        $x_1_2 = {c6 45 f9 3a c6 45 fa 5c c6 45 fb 5c c6 45 fc 00 8b 45 08 89 45 ?? c7 45 ?? 00 00 00 00 68 03 80 00 00 ff 15 ?? ?? ?? ?? c7 45 ?? 01 00 00 00 eb 09 8b 4d 03 83 c1 01 89 4d 03 83 7d 03 1a 0f 8d ?? ?? 00 00 8b 55 03 83 c2 41 88 55 f8 8d 45 f8 50 ff 15 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

