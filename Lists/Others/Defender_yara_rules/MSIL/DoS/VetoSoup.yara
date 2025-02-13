rule DoS_MSIL_VetoSoup_A_2147817774_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:MSIL/VetoSoup.A!dha"
        threat_id = "2147817774"
        type = "DoS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VetoSoup"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "alldelete.Properties.Resources" wide //weight: 50
        $x_50_2 = "/c  USER32.DLL,LockWorkStation" wide //weight: 50
        $x_50_3 = "Process Monitor|Wireshark|Process Explor|NetWorx|NetLimiter|tcpdump|netcat|Network Monitor|Intercepter-NG" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

