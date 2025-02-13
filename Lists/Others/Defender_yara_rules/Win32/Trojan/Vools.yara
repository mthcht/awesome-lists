rule Trojan_Win32_Vools_RB_2147852679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vools.RB!MTB"
        threat_id = "2147852679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vools"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "{EB0Z85-37F8-D52" ascii //weight: 5
        $x_10_2 = "C:\\Windows\\system32\\rdptaf.xsl" ascii //weight: 10
        $x_10_3 = "WINDOWS\\system32\\rdphlc.dat" wide //weight: 10
        $x_1_4 = "57 69 6e 64 6f 77 73 20 35 2e 31 00" ascii //weight: 1
        $x_1_5 = "%s\\svchost.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

