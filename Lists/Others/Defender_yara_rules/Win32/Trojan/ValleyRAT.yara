rule Trojan_Win32_ValleyRAT_EC_2147913492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.EC!MTB"
        threat_id = "2147913492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c6 83 e0 0f 8a 04 08 30 04 16 46 3b f3 72 f0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

