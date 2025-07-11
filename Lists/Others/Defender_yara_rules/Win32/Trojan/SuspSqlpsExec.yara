rule Trojan_Win32_SuspSqlpsExec_A_2147946092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSqlpsExec.A"
        threat_id = "2147946092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSqlpsExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sqlps.exe" wide //weight: 10
        $x_1_2 = "net.webclient" wide //weight: 1
        $x_1_3 = "invoke-expression" wide //weight: 1
        $x_1_4 = "iex(" wide //weight: 1
        $n_20_5 = "$env:tempcmd" wide //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

