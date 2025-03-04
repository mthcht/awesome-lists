rule Trojan_Win32_Njrat_RPF_2147840060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Njrat.RPF!MTB"
        threat_id = "2147840060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Njrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INETGET" wide //weight: 1
        $x_1_2 = "ipmasheen.xyz" wide //weight: 1
        $x_1_3 = "fghlkdhgso468.php" wide //weight: 1
        $x_1_4 = ".exe\" )" wide //weight: 1
        $x_1_5 = "INET_DOWNLOADWAIT" wide //weight: 1
        $x_1_6 = "INET_FORCERELOAD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

