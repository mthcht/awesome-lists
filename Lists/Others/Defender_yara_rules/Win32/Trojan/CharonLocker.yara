rule Trojan_Win32_CharonLocker_YAB_2147978496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CharonLocker.YAB!MTB"
        threat_id = "2147978496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CharonLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "OopsCharonHere" ascii //weight: 5
        $x_3_2 = "ATTENTION Egyptair" ascii //weight: 3
        $x_2_3 = "YOUR NETWORK HAS BEEN COMPROMISED" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

