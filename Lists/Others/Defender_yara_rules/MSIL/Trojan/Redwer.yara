rule Trojan_MSIL_Redwer_DD_2147785324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redwer.DD!MTB"
        threat_id = "2147785324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redwer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HereGoesTheFileToDrop" ascii //weight: 3
        $x_3_2 = "secretkey9834756823476y0283746" ascii //weight: 3
        $x_3_3 = "activetime.txt" ascii //weight: 3
        $x_3_4 = "GetFolderPath" ascii //weight: 3
        $x_3_5 = "\\WinDefender\\WindowsDefender" ascii //weight: 3
        $x_3_6 = "ExtractResource" ascii //weight: 3
        $x_3_7 = "IntelManagementConsole" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

