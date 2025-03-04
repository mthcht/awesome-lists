rule Trojan_Win32_Fakeav_DWNO_2147797369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakeav.DWNO!MTB"
        threat_id = "2147797369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeav"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d0 c0 c2 04 8a c2 24 0f bb e1 4a 40 00 d7 a2 44 4e 40 00 c0 c2 04 8a c2 24 0f d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

