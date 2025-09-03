rule Trojan_Win32_Steanoz_Z_2147949789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Steanoz.Z!MTB"
        threat_id = "2147949789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Steanoz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".invoke($" wide //weight: 1
        $x_1_2 = ".getmethod" wide //weight: 1
        $x_1_3 = ".gettype(" wide //weight: 1
        $x_1_4 = "system.reflection.assembly]::load" wide //weight: 1
        $x_1_5 = "Convert]::FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

