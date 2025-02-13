rule TrojanDownloader_MSIL_NjRAT_A_2147835634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NjRAT.A!MTB"
        threat_id = "2147835634"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 16 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 d6 0c 08 11 04 31 dc 7e ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 06 26 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_NjRAT_F_2147844641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NjRAT.F!MTB"
        threat_id = "2147844641"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 04 07 08 16 6f ?? 01 00 0a 13 05 12 05 28}  //weight: 2, accuracy: Low
        $x_2_2 = "WebClient" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_NjRAT_H_2147900190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NjRAT.H!MTB"
        threat_id = "2147900190"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 14 14 14 28}  //weight: 2, accuracy: High
        $x_2_2 = {01 13 04 11 04 16 14 a2}  //weight: 2, accuracy: High
        $x_2_3 = {11 04 17 14 a2}  //weight: 2, accuracy: High
        $x_2_4 = {11 04 14 14 14 17 28}  //weight: 2, accuracy: High
        $x_2_5 = "Invoke" wide //weight: 2
        $x_2_6 = "EntryPoint" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_NjRAT_I_2147900834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NjRAT.I!MTB"
        threat_id = "2147900834"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd.exe /c ping 1" wide //weight: 2
        $x_2_2 = "1 & del" wide //weight: 2
        $x_2_3 = "powershell -ExecutionPolicy Bypass -file" wide //weight: 2
        $x_2_4 = "New-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name" wide //weight: 2
        $x_2_5 = "-PropertyType \"String\" -force" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

