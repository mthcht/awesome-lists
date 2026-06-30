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

rule Trojan_Win64_RootkitDrv_ARD_2147972623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RootkitDrv.ARD!MTB"
        threat_id = "2147972623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RootkitDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 48 33 c0 88 54 24 24 4c 89 44 24 28 48 8d 54 24 20 48 89 4c 24 30 66 89 44 24 25 44 8d 40 18 88 44 24 27 8d 48 4b c7 44 24 20 42 53 42 53 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4b 25 44 8b c7 40 38 7b 04 8b 43 21 41 0f 95 c0 48 c1 e0 20 48 0b c1 33 d2 48 8b cd ff 15 ?? ?? ?? ?? 8b 4b 2d 45 33 c9 8b 43 29 45 33 c0 48 c1 e0 20 33 d2 48 0b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

