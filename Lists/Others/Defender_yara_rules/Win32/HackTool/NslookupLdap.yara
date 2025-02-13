rule HackTool_Win32_NslookupLdap_A_2147809952_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NslookupLdap.A"
        threat_id = "2147809952"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NslookupLdap"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nslookup" wide //weight: 1
        $x_1_2 = "-querytype=all" wide //weight: 1
        $x_1_3 = "-timeout=" wide //weight: 1
        $x_1_4 = "_ldap._tcp.dc._msdcs." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

