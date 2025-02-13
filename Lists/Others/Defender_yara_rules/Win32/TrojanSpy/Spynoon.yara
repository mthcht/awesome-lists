rule TrojanSpy_Win32_Spynoon_STEL_2147782388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Spynoon.STEL!MTB"
        threat_id = "2147782388"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ewiuegp" ascii //weight: 1
        $x_1_2 = "hneseqnpu" ascii //weight: 1
        $x_1_3 = "ksonervxd" ascii //weight: 1
        $x_1_4 = "mqvibz" ascii //weight: 1
        $x_1_5 = "pwyilobd" ascii //weight: 1
        $x_1_6 = "uretsumojyr" ascii //weight: 1
        $x_1_7 = "vcrslq" ascii //weight: 1
        $x_1_8 = "vdaepdxmjth" ascii //weight: 1
        $x_1_9 = "wtfej" ascii //weight: 1
        $x_1_10 = "xejnyi" ascii //weight: 1
        $x_1_11 = ".rdata$zzzdbg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Spynoon_STE_2147899300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Spynoon.STE!MTB"
        threat_id = "2147899300"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "roryhcrlfwcgn" ascii //weight: 1
        $x_1_2 = "onzsbtmtcuikq" ascii //weight: 1
        $x_1_3 = "eetxgbkedrug" ascii //weight: 1
        $x_1_4 = "jlaigjkakxfufs" ascii //weight: 1
        $x_1_5 = "xqutgigbhspa" ascii //weight: 1
        $x_1_6 = "%APPDATA%" ascii //weight: 1
        $x_1_7 = "ybmpccqrxhyth" ascii //weight: 1
        $x_1_8 = "xctntxjxkz" ascii //weight: 1
        $x_1_9 = "qneqcvgfyux" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

