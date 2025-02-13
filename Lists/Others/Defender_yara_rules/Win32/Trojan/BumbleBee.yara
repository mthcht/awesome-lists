rule Trojan_Win32_BumbleBee_AB_2147832614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BumbleBee.AB!MTB"
        threat_id = "2147832614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vwv045do38.dll" ascii //weight: 5
        $x_1_2 = "CSlSbD48" ascii //weight: 1
        $x_1_3 = "ITe305" ascii //weight: 1
        $x_1_4 = "AppStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BumbleBee_AC_2147832615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BumbleBee.AC!MTB"
        threat_id = "2147832615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vwe554dy80.dll" ascii //weight: 5
        $x_1_2 = "CSlSbD48" ascii //weight: 1
        $x_1_3 = "ITe305" ascii //weight: 1
        $x_1_4 = "loadtask" ascii //weight: 1
        $x_5_5 = "DRCTF.DLL" ascii //weight: 5
        $x_1_6 = "PnhubgyEctyv" ascii //weight: 1
        $x_1_7 = "RtcfvyKnbg" ascii //weight: 1
        $x_1_8 = "TsxrdPnhbug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

