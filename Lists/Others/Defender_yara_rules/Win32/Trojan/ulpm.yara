rule Trojan_Win32_ulpm_RDA_2147896310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ulpm.RDA!MTB"
        threat_id = "2147896310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ulpm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 ba 0a 00 00 00 29 f8 d1 f8 89 d5 99 f7 fd 83 c2 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

