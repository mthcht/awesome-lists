rule Trojan_Win32_PsLoadz_A_2147957230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsLoadz.A!MTB"
        threat_id = "2147957230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$_ -bxor" wide //weight: 1
        $x_1_2 = "-join" wide //weight: 1
        $x_1_3 = ".Assembly]::$" wide //weight: 1
        $x_1_4 = "]::Decompress" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

