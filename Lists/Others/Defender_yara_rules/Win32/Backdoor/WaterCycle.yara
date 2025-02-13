rule Backdoor_Win32_WaterCycle_A_2147750351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/WaterCycle.A!dha"
        threat_id = "2147750351"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "WaterCycle"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Proxy-Authorization: Basic VXNlci0wMDE6MTExMQ==" ascii //weight: 2
        $x_2_2 = ".?AVDUpdate@@" ascii //weight: 2
        $x_2_3 = ".?AVGUpdate@@" ascii //weight: 2
        $x_2_4 = ".?AVOUpdate@@" ascii //weight: 2
        $x_1_5 = ".?AVCloudBase@@" ascii //weight: 1
        $x_1_6 = "content.dropboxa" ascii //weight: 1
        $x_1_7 = "n&code=%s&grant_" ascii //weight: 1
        $x_1_8 = "pe=onedrive.read" ascii //weight: 1
        $x_1_9 = {6c 6f 67 69 c7 ?? ?? 6e 2e 6c 69 c7 ?? ?? 76 65 2e 63}  //weight: 1, accuracy: Low
        $x_2_10 = {12 3f e0 56 c7 ?? ?? 90 ac b2 09}  //weight: 2, accuracy: Low
        $x_2_11 = {f7 e6 8b c6 c1 ea 03 8d 0c 92 03 c9 2b c1 8a 44 ?? ?? 30 04 1e 46 3b f7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

