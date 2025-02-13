rule Trojan_Win32_WarZone_RDA_2147893096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WarZone.RDA!MTB"
        threat_id = "2147893096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WarZone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c1 99 f7 ff 8a 44 15 98 30 04 31 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

