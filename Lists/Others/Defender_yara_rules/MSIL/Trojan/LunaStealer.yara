rule Trojan_MSIL_LunaStealer_NS_2147929146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LunaStealer.NS!MTB"
        threat_id = "2147929146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LunaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Keylogger" ascii //weight: 2
        $x_1_2 = "ENCRYPTED:CPB7ti0A5zas/0dF4XBKzDiUIfmQ5RgrLQvDrYCST4M=" ascii //weight: 1
        $x_1_3 = "ENCRYPTED:cYs6KSRyO3yMrWGQDOmKxivjCVxRHP8X2elXQtdRGbiad1fFkV3DBIHK2EbuIBDA" ascii //weight: 1
        $x_1_4 = "AntiAnalysis" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "passwords.txt" ascii //weight: 1
        $x_1_7 = "klfhbdnlcfcaccoakhceodhldjojboga" ascii //weight: 1
        $x_1_8 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii //weight: 1
        $x_1_9 = "oooiblbdpdlecigodndinbpfopomaegl" ascii //weight: 1
        $x_1_10 = "aanjhgiamnacdfnlfnmgehjikagdbafd" ascii //weight: 1
        $x_1_11 = "akoiaibnepcedcplijmiamnaigbepmcb" ascii //weight: 1
        $x_1_12 = "ajkhoeiiokighlmdnlakpjfoobnjinie" ascii //weight: 1
        $x_1_13 = "dmdimapfghaakeibppbfeokhgoikeoci" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

