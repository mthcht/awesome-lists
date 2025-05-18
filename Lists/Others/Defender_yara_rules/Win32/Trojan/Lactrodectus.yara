rule Trojan_Win32_Lactrodectus_Z_2147941686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lactrodectus.Z!MTB"
        threat_id = "2147941686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lactrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f8 2b 75 0f b8 3e 00 00 00 66 89 44 24 24 e9 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

