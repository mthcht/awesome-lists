rule Trojan_Win32_Zopt_A_2147646656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zopt.A"
        threat_id = "2147646656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zopt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "brumamkcwgrm.brumamkcwgrm" ascii //weight: 2
        $x_1_2 = "ixnfplsr" ascii //weight: 1
        $x_2_3 = "20F08D1D-10F1-4EEB-BF27-ABC45E7E761D" ascii //weight: 2
        $x_2_4 = "F94859FD-8ACE-4D27-B58B-E5BC79408CFF" ascii //weight: 2
        $x_2_5 = "nqwvdgkdzkuBs0ixnfplsr" ascii //weight: 2
        $x_2_6 = "Administrator\\Application DataCLIENT" ascii //weight: 2
        $x_1_7 = "impenc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zopt_A_2147646656_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zopt.A"
        threat_id = "2147646656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zopt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "adfamkcwpr.adfamkcwpr" ascii //weight: 2
        $x_2_2 = "{27DAE335-5892-4D9E-9210-9AE2717AFAAB}" ascii //weight: 2
        $x_2_3 = "chkamkcwhst.chkamkcwhst" ascii //weight: 2
        $x_2_4 = "{A1FB1B5E-7111-44ED-B402-EA929CD33D9A}" ascii //weight: 2
        $x_2_5 = "nqwvdgkdzkoosts5ixnfplsr" ascii //weight: 2
        $x_2_6 = "callmthd" ascii //weight: 2
        $x_2_7 = "Administrator\\Application DataCLIENT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

