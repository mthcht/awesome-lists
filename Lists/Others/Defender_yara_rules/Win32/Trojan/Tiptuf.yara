rule Trojan_Win32_Tiptuf_A_2147637441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tiptuf.A"
        threat_id = "2147637441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiptuf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&engine=%s&query=%s&ie=%s" ascii //weight: 2
        $x_3_2 = "TCPIP Pass-through Filter" ascii //weight: 3
        $x_3_3 = "<a class=\"yschttl spt\" href" ascii //weight: 3
        $x_1_4 = "svchost.exe -k netsvcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

