rule Trojan_Win32_RevShellEnum_A_2147959774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShellEnum.A!MTB"
        threat_id = "2147959774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShellEnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "net user" wide //weight: 1
        $x_1_2 = "echo" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
        $x_1_4 = "ipconfig /all" wide //weight: 1
        $x_1_5 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_6 = "curl" wide //weight: 1
        $x_1_7 = "-body $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

