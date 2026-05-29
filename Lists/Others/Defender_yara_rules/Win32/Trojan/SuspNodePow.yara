rule Trojan_Win32_SuspNodePow_Z_2147970582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspNodePow.Z!MTB"
        threat_id = "2147970582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNodePow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 [0-80] 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

