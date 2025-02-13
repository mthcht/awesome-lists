rule Trojan_Win32_LummaStealers_OMK_2147929737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealers.OMK!MTB"
        threat_id = "2147929737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealers"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 56 64 8b 3d 30 00 00 00 8b 7f 0c 8b 77 0c 8b 06 8b 00 8b 40 18 a3 70 14 43 00 5e 5f 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

