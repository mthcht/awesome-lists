rule Trojan_Win64_ForFilesAbuse_A_2147925255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ForFilesAbuse.A!dha"
        threat_id = "2147925255"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ForFilesAbuse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\System32\\forfiles.exe /p C:\\ /m Windows /c powershell . \\*i*\\*2\\msh*e https" wide //weight: 1
        $x_1_2 = "C:\\Windows\\SysWow64\\forfiles.exe /p C:\\ /m Windows /c powershell . \\*i*\\*4\\msh*e https" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

