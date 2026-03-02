rule Backdoor_Win64_GoverKick_A_2147963959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/GoverKick.A!dha"
        threat_id = "2147963959"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "GoverKick"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 65 36 34 2e 64 6c 6c 00 47 65 74 49 6d 61 67 65 00 48 65 6c 6c 6f 00 52 75 6e 44 4c 4c 57}  //weight: 2, accuracy: High
        $x_1_2 = "Task queue full, rejecting: %s" ascii //weight: 1
        $x_1_3 = "Proxy returned error status: %d" ascii //weight: 1
        $x_1_4 = "Task queued: %s (ID: %s)" ascii //weight: 1
        $x_1_5 = "Generated host fingerprint: Hostname=%s, MAC=%s, BootTime=%s" ascii //weight: 1
        $x_1_6 = "Sending registration: ID=%s, HostID=%s" ascii //weight: 1
        $x_1_7 = "Global\\MyGoAppUniqueMutexName" ascii //weight: 1
        $x_1_8 = {70 61 74 68 09 74 65 36 34 0a 6d 6f 64 09 74 65 36 34 09 28 64 65 76 65 6c 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

