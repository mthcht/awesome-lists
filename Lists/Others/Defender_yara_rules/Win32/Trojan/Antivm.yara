rule Trojan_Win32_Antivm_YD_2147741298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivm.YD!MTB"
        threat_id = "2147741298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*ERAWMV*" wide //weight: 1
        $x_1_2 = "*LAUTRIV*" wide //weight: 1
        $x_1_3 = "*XOBV*" wide //weight: 1
        $x_1_4 = "lld.lldeibs" wide //weight: 1
        $x_1_5 = "lld.plehgbd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

