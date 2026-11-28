rule TrojanDownloader_Win64_LummaStealer_CCJX_2147940447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/LummaStealer.CCJX!MTB"
        threat_id = "2147940447"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "powershell -Command \"Add-MpPreference -ExclusionPath" wide //weight: 2
        $x_2_2 = "powershell -Command \"Invoke-WebRequest -Uri" wide //weight: 2
        $x_2_3 = "-OutFile" wide //weight: 2
        $x_1_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 6f 00 73 00 61 00 6c 00 6f 00 6c 00 6f 00 2f 00 6a 00 61 00 6d 00 62 00 65 00 72 00 2f 00 72 00 61 00 77 00 2f 00 72 00 65 00 66 00 73 00 2f 00 68 00 65 00 61 00 64 00 73 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 [0-31] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "http://77.223.119.85/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win64_LummaStealer_RS_2147982979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/LummaStealer.RS!MTB"
        threat_id = "2147982979"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main: start" ascii //weight: 1
        $x_1_2 = "main: unpack" ascii //weight: 1
        $x_1_3 = "main: payload len" ascii //weight: 1
        $x_1_4 = "spawn: begin" ascii //weight: 1
        $x_1_5 = "spawn: staged" ascii //weight: 1
        $x_1_6 = "disk drop" ascii //weight: 1
        $x_1_7 = "drop written" ascii //weight: 1
        $x_1_8 = "disk shell failed" ascii //weight: 1
        $x_1_9 = "loadpedisk blocked" ascii //weight: 1
        $x_1_10 = "pe_stub_spawn.log" ascii //weight: 1
        $x_1_11 = "ShellExecuteEx failed" ascii //weight: 1
        $x_1_12 = "CreateProcess failed" ascii //weight: 1
        $x_1_13 = "loadpe (self-hollow, no drop)" ascii //weight: 1
        $x_1_14 = "NtUnmapViewOfSection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

