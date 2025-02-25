rule Trojan_Win32_NetworkSniffing_ZPA_2147934414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkSniffing.ZPA"
        threat_id = "2147934414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkSniffing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\tshark.exe" wide //weight: 1
        $x_1_2 = " -i " wide //weight: 1
        $x_1_3 = " -c 5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetworkSniffing_ZPB_2147934415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkSniffing.ZPB"
        threat_id = "2147934415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkSniffing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pktmon" wide //weight: 1
        $x_1_2 = "filter add -p 445" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetworkSniffing_ZPB_2147934415_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkSniffing.ZPB"
        threat_id = "2147934415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkSniffing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pktmon" wide //weight: 1
        $x_1_2 = "start --etw " wide //weight: 1
        $x_1_3 = " -f " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

