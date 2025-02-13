rule Trojan_Win64_T1558_StealOrForgeKerberosTickets_A_2147846078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1558_StealOrForgeKerberosTickets.A"
        threat_id = "2147846078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1558_StealOrForgeKerberosTickets"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kerberos::list" wide //weight: 10
        $x_10_2 = "kerberos::clist" wide //weight: 10
        $x_10_3 = "kerberos::hash" wide //weight: 10
        $x_10_4 = "kerberos::ptc" wide //weight: 10
        $x_10_5 = "kerberos::ptt" wide //weight: 10
        $x_10_6 = "kerberos::tgt" wide //weight: 10
        $x_10_7 = "lsadump::lsa" wide //weight: 10
        $x_10_8 = "sekurlsa::kerberos" wide //weight: 10
        $x_10_9 = "sekurlsa::krbtgt" wide //weight: 10
        $x_10_10 = "sekurlsa::tickets" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

