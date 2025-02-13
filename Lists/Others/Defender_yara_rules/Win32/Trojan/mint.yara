rule Trojan_Win32_mint_RDD_2147852971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/mint.RDD!MTB"
        threat_id = "2147852971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "mint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c1 ba 57 41 0e 98 89 c8 f7 ea 8d 04 0a c1 f8 08 89 c2 89 c8 c1 f8 1f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

