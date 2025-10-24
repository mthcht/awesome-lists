rule Trojan_Win32_RegPersis_B_2147955909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegPersis.B!MTB"
        threat_id = "2147955909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegPersis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".replace" wide //weight: 1
        $x_1_2 = "[char][convert]::ToInt32(" wide //weight: 1
        $x_1_3 = ".Substring($" wide //weight: 1
        $x_1_4 = "split" wide //weight: 1
        $x_1_5 = "-join" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

