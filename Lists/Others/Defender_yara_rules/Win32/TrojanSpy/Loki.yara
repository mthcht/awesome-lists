rule TrojanSpy_Win32_Loki_MC_2147755494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Loki.MC!MTB"
        threat_id = "2147755494"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 e8 28 ff ff ff b8 ?? ?? ?? ?? 31 c9 68 ?? ?? ?? ?? 5a 80 34 01 ?? 41 39 d1 75 ?? 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Loki_CM_2147755504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Loki.CM!MTB"
        threat_id = "2147755504"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 e8 3a ff ff ff b8 ?? ?? ?? ?? 31 c9 68 ?? ?? ?? ?? 5a 80 34 01 ?? 41 39 d1 75 ?? 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Loki_MF_2147755583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Loki.MF!MTB"
        threat_id = "2147755583"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b 44 24 [0-48] 50 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 c9 68 ?? ?? ?? ?? 5a 80 34 01 ?? 41 39 d1 ?? ?? 05 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

