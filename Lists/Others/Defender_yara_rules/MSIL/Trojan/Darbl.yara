rule Trojan_MSIL_Darbl_A_2147733701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darbl.A"
        threat_id = "2147733701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darbl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "set_Passwords" ascii //weight: 1
        $x_1_2 = "get_Passwords" ascii //weight: 1
        $x_2_3 = {00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 42 00 61 00 6c 00 64 00 72 00 2e 00 65 00 78 00 65}  //weight: 2, accuracy: High
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "UploadData" ascii //weight: 1
        $x_1_6 = "get_RunningProcess" ascii //weight: 1
        $x_1_7 = "get_InstalledPrograms" ascii //weight: 1
        $x_1_8 = "get_Resolution" ascii //weight: 1
        $x_1_9 = "get_HWID" ascii //weight: 1
        $x_2_10 = {4c 00 54 00 45 00 78 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

