rule TrojanDownloader_Win64_AsyncRAT_A_2147851168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRAT.A!MTB"
        threat_id = "2147851168"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\Public\\main.exe" wide //weight: 2
        $x_2_2 = "://116.62.11.90/main.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_AsyncRAT_B_2147851259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRAT.B!MTB"
        threat_id = "2147851259"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ly9wYXN0ZS5mby9yYXcvN" ascii //weight: 2
        $x_2_2 = "attrib +h" ascii //weight: 2
        $x_2_3 = "\\.\\PhysicalDrive0" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_AsyncRAT_C_2147889004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRAT.C!MTB"
        threat_id = "2147889004"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd.exe /c curl -o %temp%\\" ascii //weight: 2
        $x_2_2 = "powershell start -WindowStyle hidden %temp%\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_AsyncRAT_D_2147890063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRAT.D!MTB"
        threat_id = "2147890063"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6d 61 69 6e ?? 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateProcessW" ascii //weight: 1
        $x_1_3 = "RtlGetNtVersionNumbers" ascii //weight: 1
        $x_2_4 = {2f 6d 61 69 6e ?? 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win64_AsyncRAT_E_2147919849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRAT.E!MTB"
        threat_id = "2147919849"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "RatDownload\\x64\\Release\\RatLoader.pdb" ascii //weight: 4
        $x_2_2 = "download/Realease" ascii //weight: 2
        $x_2_3 = "APPDATA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_AsyncRAT_PAGU_2147956753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRAT.PAGU!MTB"
        threat_id = "2147956753"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 18}  //weight: 2, accuracy: High
        $x_1_2 = "ClassLibrary3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

