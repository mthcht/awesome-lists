rule Trojan_Win32_PWSZbot_GSB_2147809224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PWSZbot.GSB!MTB"
        threat_id = "2147809224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSZbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 70 60 8b 45 fc 03 c6 83 c0 ?? 8b f0 8b 38 b8 0c 00 00 00 2b f0 8b 06 03 7d fc 89 45 f4 83 ee ?? 33 d2 8b 5d 0c c3}  //weight: 10, accuracy: Low
        $x_10_2 = {8b d1 8b 5d f0 33 c0 42 8b 0a 40 fe c1 fe c9 75 f6 48 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PWSZbot_HBAI_2147809825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PWSZbot.HBAI!MTB"
        threat_id = "2147809825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSZbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {52 21 52 d7 30 64 98 24 4a b8 69 03 21 32 89 ff 43 2e f1 75 a9}  //weight: 10, accuracy: High
        $x_10_2 = {a3 05 17 8c 0a 08 c2 31 f1 29 fe 41 47}  //weight: 10, accuracy: High
        $x_1_3 = "URLDownloadToFile" ascii //weight: 1
        $x_1_4 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PWSZbot_GMM_2147811653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PWSZbot.GMM!MTB"
        threat_id = "2147811653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSZbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 8b 75 08 8a 0e 8a 07 3b c1 75 08 85 c0 74 07 46 47 eb f0 33 c0 40 5f 5e 8b e5 5d c2 08 00}  //weight: 10, accuracy: High
        $x_10_2 = {8a 07 32 c3 88 06 47 2b f2 49 75 f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PWSZbot_GNT_2147814168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PWSZbot.GNT!MTB"
        threat_id = "2147814168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSZbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 33 07 08 8b ?? ?? ?? ?? c1 c0 ?? ba ?? ?? ?? ?? c1 ca 15 03 c2 c1 c8 16 89 45 b8 e9 d3 01 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {8b f8 23 fa 3b fa 0f 85 ?? ?? ?? ?? c1 e1 ?? c1 e0 ?? eb ec 41 33 df}  //weight: 10, accuracy: Low
        $x_1_3 = "hOptnRee" ascii //weight: 1
        $x_1_4 = "d3d8thk.dlm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

