rule Trojan_Win32_Weelsof_RYM_2147752189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Weelsof.RYM!MTB"
        threat_id = "2147752189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Weelsof"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe e6 77 00 00 eb 84 00 8a 1c 30 [0-31] 80 f3 ?? eb [0-31] f6 d3 eb [0-31] 80 f3 ?? eb [0-37] 88 1c 30 [0-31] 46 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ff e6 77 00 00 [0-31] eb 8f 00 8a 1c 38 90 [0-31] eb [0-31] 80 f3 [0-31] f6 d3 [0-31] 80 f3 [0-31] 88 1c 38 90 [0-31] 47 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

