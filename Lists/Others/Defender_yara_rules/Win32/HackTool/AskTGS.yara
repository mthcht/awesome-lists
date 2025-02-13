rule HackTool_Win32_AskTGS_2147740619_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AskTGS"
        threat_id = "2147740619"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AskTGS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "asktgs kerberos client" ascii //weight: 3
        $x_1_2 = "* ticket in file '%s'" ascii //weight: 1
        $x_1_3 = "kull_m_kerberos_helper_util_saverepaskrbcred" ascii //weight: 1
        $x_1_4 = "kull_m_kerberos_asn1_helper_build_krbcred" ascii //weight: 1
        $x_1_5 = "kull_m_kerberos_helper_util_ptt_data" ascii //weight: 1
        $x_1_6 = "tgt.kirbi" ascii //weight: 1
        $x_1_7 = "LsaCallAuthenticationPackage" ascii //weight: 1
        $x_1_8 = "krbcredinfo" ascii //weight: 1
        $x_1_9 = "ticket-info" ascii //weight: 1
        $x_1_10 = "gentilkiwi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

