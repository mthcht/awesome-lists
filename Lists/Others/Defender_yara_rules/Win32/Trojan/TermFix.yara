rule Trojan_Win32_TermFix_DA_2147974716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TermFix.DA!MTB"
        threat_id = "2147974716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TermFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "iex(irm " wide //weight: 1
        $x_1_3 = " -UseBasicParsing)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

