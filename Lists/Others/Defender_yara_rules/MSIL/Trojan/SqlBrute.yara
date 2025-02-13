rule Trojan_MSIL_SqlBrute_A_2147788131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SqlBrute.A!MTB"
        threat_id = "2147788131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SqlBrute"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winlogon.pdb" ascii //weight: 1
        $x_1_2 = "sa@123456" ascii //weight: 1
        $x_1_3 = "exec sp_password null,' 123!#@ABCabc','websa'" ascii //weight: 1
        $x_1_4 = "exec sp_password null,' 123!#@ABCabc','6door'" ascii //weight: 1
        $x_1_5 = "winlogon.Resources.sqlAdmin.txt" ascii //weight: 1
        $x_1_6 = "winlogon.Resources.sqlMssql.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

