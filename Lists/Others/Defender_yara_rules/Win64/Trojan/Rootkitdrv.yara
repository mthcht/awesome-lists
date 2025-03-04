rule Trojan_Win64_RootkitDrv_RTB_2147796963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RootkitDrv.RTB!MTB"
        threat_id = "2147796963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RootkitDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QufanPacRegRulBuff" ascii //weight: 1
        $x_10_2 = "\\MirBt_D.pdb" ascii //weight: 10
        $x_10_3 = "\\MirBt_F.pdb" ascii //weight: 10
        $x_10_4 = "\\FiveSysMirBt_D.pdb" ascii //weight: 10
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "GetStartupInfoW" ascii //weight: 1
        $x_1_7 = "de-Convert\\c32rtomb.cpp" ascii //weight: 1
        $x_1_8 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_RootkitDrv_RTC_2147796964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RootkitDrv.RTC!MTB"
        threat_id = "2147796964"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RootkitDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\FiveSys_1\\x64\\Debug\\FiveSys.pdb" ascii //weight: 10
        $x_1_2 = "KeBugCheckEx" ascii //weight: 1
        $x_1_3 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_4 = "Q2yd0\\*d0\\*d0\\*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

