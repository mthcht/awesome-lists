rule Trojan_Win32_NekoStealer_NE_2147828311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NekoStealer.NE!MTB"
        threat_id = "2147828311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NekoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bayi wevuxira bototajikasixev wawe" ascii //weight: 1
        $x_1_2 = "gicupod" ascii //weight: 1
        $x_1_3 = "Tetoyawomelob" ascii //weight: 1
        $x_1_4 = "yorujepenuvabu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NekoStealer_RPL_2147829758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NekoStealer.RPL!MTB"
        threat_id = "2147829758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NekoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f7 8a 04 2a c0 e0 05 30 04 19 41 3b ce 72 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

