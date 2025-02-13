rule TrojanDownloader_Win64_Farfli_UR_2147812159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Farfli.UR!MTB"
        threat_id = "2147812159"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://194.146.84.243:4397/77" ascii //weight: 1
        $x_1_2 = "\\rundll3222.exe" ascii //weight: 1
        $x_1_3 = "ojbkcg.exe" ascii //weight: 1
        $x_1_4 = "\\svchost.txt" ascii //weight: 1
        $x_1_5 = "C:\\ProgramData\\svchost.txt" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
        $x_1_7 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Farfli_GNN_2147813280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Farfli.GNN!MTB"
        threat_id = "2147813280"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "156.234.65" ascii //weight: 1
        $x_1_2 = "\\Documents\\svchost.txt" ascii //weight: 1
        $x_1_3 = "\\Documents\\1.rar" ascii //weight: 1
        $x_1_4 = "\\Documents\\jdi.lnk" ascii //weight: 1
        $x_1_5 = "\\Release\\sdasdasd.pdb" ascii //weight: 1
        $x_1_6 = "Public\\Documents\\7z.exe" ascii //weight: 1
        $x_1_7 = "C:\\ProgramData\\7z.exe" ascii //weight: 1
        $x_1_8 = "URLDownloadToFile" ascii //weight: 1
        $x_1_9 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

