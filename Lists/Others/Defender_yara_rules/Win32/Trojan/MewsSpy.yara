rule Trojan_Win32_MewsSpy_CCJT_2147929842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MewsSpy.CCJT!MTB"
        threat_id = "2147929842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MewsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 56 04 8a 14 0a 32 56 fc 41 88 54 01 ff 3b 0e 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

