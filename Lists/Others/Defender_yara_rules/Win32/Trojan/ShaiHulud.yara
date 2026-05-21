rule Trojan_Win32_ShaiHulud_ZK_2147969848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShaiHulud.ZK!MTB"
        threat_id = "2147969848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShaiHulud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grep -" wide //weight: 1
        $x_1_2 = "tr -d '\\0'" wide //weight: 1
        $x_1_3 = "isSecret\":true" wide //weight: 1
        $x_1_4 = "[^\"]+\":\"[^\"]*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

