rule Trojan_Win32_Rm3_A_2147898481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rm3.A!MTB"
        threat_id = "2147898481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rm3"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 03 cf 0f b7 c9 0f af c8 66 03 cf 0f b7 c9 0f af c8 66 03 cf 0f b7 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

