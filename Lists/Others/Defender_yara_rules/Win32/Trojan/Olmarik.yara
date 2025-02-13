rule Trojan_Win32_Olmarik_A_2147851636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Olmarik.A!MTB"
        threat_id = "2147851636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Olmarik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 6a 3e 33 d2 5b f7 f3 83 fa 1a 7d ?? 80 c2 61 eb ?? 83 fa 34 7d ?? 80 c2 27 eb ?? 80 ea 04 d1 45 fc 88 14 0f 47 3b fe 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

