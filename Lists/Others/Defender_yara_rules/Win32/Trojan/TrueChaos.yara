rule Trojan_Win32_TrueChaos_DB_2147966248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrueChaos.DB!MTB"
        threat_id = "2147966248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrueChaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = "ftp://47.237.15.197" wide //weight: 1
        $x_1_3 = "winrar.exe x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

