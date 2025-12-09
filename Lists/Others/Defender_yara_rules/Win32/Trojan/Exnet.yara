rule Trojan_Win32_Exnet_GVA_2147959030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Exnet.GVA!MTB"
        threat_id = "2147959030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 83 c4 08 8d 71 01 8a 11 41 84 d2 75 f9 33 d2 2b ce 74 09 80 34 02 bb 42 3b d1 72 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

