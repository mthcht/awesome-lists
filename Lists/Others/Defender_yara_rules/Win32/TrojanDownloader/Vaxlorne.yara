rule TrojanDownloader_Win32_Vaxlorne_A_2147598277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vaxlorne.A"
        threat_id = "2147598277"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vaxlorne"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Toolhelp32ReadProcessMemory" ascii //weight: 20
        $x_5_2 = "Files\\Microsoft Shared\\Windows Live\\" ascii //weight: 5
        $x_5_3 = "deleteself.bat" ascii //weight: 5
        $x_1_4 = "%s\\%s@%s.log" ascii //weight: 1
        $x_1_5 = "DownloadRandomUrlFile::" ascii //weight: 1
        $x_1_6 = "KillProcessByFileName(%s)" ascii //weight: 1
        $x_1_7 = ":= reg.ReadInteger('" ascii //weight: 1
        $x_1_8 = "_count.html?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Vaxlorne_B_2147598870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vaxlorne.B"
        threat_id = "2147598870"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vaxlorne"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".co.kr/" ascii //weight: 10
        $x_2_2 = "deleteself.bat" ascii //weight: 2
        $x_2_3 = "KillProcessByFileName(%s)" ascii //weight: 2
        $x_2_4 = ".CloneAndReg_Self;" ascii //weight: 2
        $x_2_5 = "before \"reg.OpenKey(" ascii //weight: 2
        $x_2_6 = "_count.html?id=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

