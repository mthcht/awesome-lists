rule Trojan_Win64_FileCoder_NF_2147893871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c8 ff eb 31 48 8b cb e8 a5 00 00 00 48 85 c0 75 05 83 cf ?? eb 0e 48 89 05 b8 1c 05 00 48 89 05 99 1c 05 00 33 c9 e8 5a 32}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 41 3b 11 41 8d 40 01 0f b7 51 02 41 0f 44 c0 48 83 c1 02 49 83 c1 02 44 8b c0 66 83 fa 3d 75 df}  //weight: 2, accuracy: High
        $x_1_2 = {49 8b 0a 45 8b c7 66 83 39 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 41 01 48 83 f8 ?? 7c dc 31 c0 eb 19 48 89 c1 48 c1 e0 ?? 48 8d 15 43 2b 59 00 48 01 c2}  //weight: 5, accuracy: Low
        $x_1_2 = "ZZXuK7T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "File encrypted and original deleted" ascii //weight: 2
        $x_1_2 = "Error encrypting file" ascii //weight: 1
        $x_2_3 = "Send X Bitcoin to address Y to theoretically decrypt them" ascii //weight: 2
        $x_1_4 = "Your files have been theoretically encrypted" ascii //weight: 1
        $x_1_5 = "Starting theoretical encryption of directory:" ascii //weight: 1
        $x_2_6 = "THEORETICAL RANSOM NOTE" ascii //weight: 2
        $x_1_7 = "Generated Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RansomwareWindowClass" ascii //weight: 2
        $x_1_2 = "cmd /c reg delete HKCU\\Software\\Classes\\ms-settings /f" ascii //weight: 1
        $x_1_3 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_5 = "Your PC is Encrypted" ascii //weight: 1
        $x_1_6 = "lol, maddox" ascii //weight: 1
        $x_1_7 = "lets sit down as your files are encrypted and then deleted" ascii //weight: 1
        $x_1_8 = "don't try to reset, your pc is already fucked by the time you read this line." ascii //weight: 1
        $x_1_9 = "file decryption is impossible. the decryption keys have already been deleted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransom.jpg" wide //weight: 1
        $x_2_2 = "vssadmin delete shadows /all /quiet" wide //weight: 2
        $x_1_3 = "keylog.txt" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "Set-MpPreference -DisableRealtimeMonitoring $true" wide //weight: 1
        $x_1_6 = "net stop WinDefend" wide //weight: 1
        $x_2_7 = "DECRYPT_OR_LOSE_EVERYTHING.txt" wide //weight: 2
        $x_1_8 = "YOUR SYSTEM IS LOCKED" wide //weight: 1
        $x_2_9 = "RansomWindow" wide //weight: 2
        $x_1_10 = "wmic shadowcopy call create" wide //weight: 1
        $x_1_11 = "sc config wuauserv start=disabled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_ARAZ_2147933262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.ARAZ!MTB"
        threat_id = "2147933262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c8 89 c1 48 8d 55 a0 48 8b 85 c8 04 00 00 48 01 d0 88 08 48 83 85 c8 04 00 00 01 48 8b 85 c8 04 00 00 48 3b 85 a8 04 00 00 72 a1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

