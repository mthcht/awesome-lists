rule Trojan_MSIL_Glimpse_SA_2147902109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Glimpse.SA!MTB"
        threat_id = "2147902109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Glimpse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schemas.microsoft.com/winfx/2006/xaml" ascii //weight: 1
        $x_1_2 = "dns_upload_command_file_name_path" ascii //weight: 1
        $x_1_3 = "newPanel.exe" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "\\Debug\\newPanel.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

