rule Backdoor_Win64_ValleyRAT_GMH_2147963603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ValleyRAT.GMH!MTB"
        threat_id = "2147963603"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 b8 cd cc cc cc 41 f7 e1 80 c1 ?? 49 8d 43 ?? 43 30 4c 10 ?? 45 33 db c1 ea 03 8d 0c 92 03 c9 44 3b c9 4c 0f 45 d8 41 ff c1 44 3b cb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_ValleyRAT_GHT_2147963758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ValleyRAT.GHT!MTB"
        threat_id = "2147963758"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d0 c6 85 ?? ?? ?? ?? 53 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 70 c6 85 ?? ?? ?? ?? 00 48 8d 95 ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 89 85 ?? ?? ?? ?? 48 83 bd}  //weight: 10, accuracy: Low
        $x_1_2 = "Windows\\syssteeme.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_ValleyRAT_GFH_2147964336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ValleyRAT.GFH!MTB"
        threat_id = "2147964336"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ProgramData%\\Venlnk" ascii //weight: 1
        $x_1_2 = "\\venSuccess.ini" ascii //weight: 1
        $x_1_3 = "\\venwin.lock" ascii //weight: 1
        $x_1_4 = "USDT hijack started" ascii //weight: 1
        $x_1_5 = "shutdown /s /f /t 0" ascii //weight: 1
        $x_1_6 = "\\DisplaySessionContainers.log" ascii //weight: 1
        $x_1_7 = "EnableOfflineKeyboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_ValleyRAT_GKK_2147971235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ValleyRAT.GKK!MTB"
        threat_id = "2147971235"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 0f b6 04 31 4d 8d 52 ?? 48 8b 0f 33 d2 41 f7 f3 b8 ?? ?? ?? ?? 40 02 d5 41 30 54 0a ?? 41 f7 e0 49 8d 41 ?? 45 33 c9 c1 ea 03 8d 0c 92 03 c9 44 3b c1 4c 0f 45 c8 41 ff c0 44 3b c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_ValleyRAT_GKM_2147971239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ValleyRAT.GKM!MTB"
        threat_id = "2147971239"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 04 03 99 f7 7d ?? 80 c2 3d 30 14 31 43}  //weight: 5, accuracy: Low
        $x_5_2 = {03 c0 8b ce 2b c8 f7 d9 1b c9 23 d9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

