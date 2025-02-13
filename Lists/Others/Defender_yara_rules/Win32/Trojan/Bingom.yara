rule Trojan_Win32_Bingom_RM_2147793786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingom.RM!MTB"
        threat_id = "2147793786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ef 50 00 00 66 31 85 ?? ?? ?? ?? 6a 06 a5 59 66 8b 54 4d ?? 8d 44 4d ?? 66 31 10 49 3b cb 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingom_RPF_2147838303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingom.RPF!MTB"
        threat_id = "2147838303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "INETGET (" wide //weight: 1
        $x_1_2 = {69 00 70 00 6d 00 61 00 73 00 68 00 65 00 65 00 6e 00 2e 00 78 00 79 00 7a 00 2f 00 [0-16] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".exe\" )" wide //weight: 1
        $x_1_4 = "INET_DOWNLOADBACKGROUND = 1" wide //weight: 1
        $x_1_5 = "INET_IGNORESSL = 2" wide //weight: 1
        $x_1_6 = "INET_FORCERELOAD = 1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

