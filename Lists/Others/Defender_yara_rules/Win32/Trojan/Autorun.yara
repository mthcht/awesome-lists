rule Trojan_Win32_AutoRun_A_2147750010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoRun.A!ibt"
        threat_id = "2147750010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoRun"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "open=AutoRun.exe" ascii //weight: 1
        $x_1_2 = "shell\\1=Open" ascii //weight: 1
        $x_1_3 = "shell\\1\\Command=AutoRun.exe" ascii //weight: 1
        $x_1_4 = "shell\\2\\Command=AutoRun.exe" ascii //weight: 1
        $x_1_5 = "shellexecute=AutoRun.exe" ascii //weight: 1
        $x_1_6 = "Unable to write to C:\\AUTORUN.INF" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoRun_BFC_2147783778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoRun.BFC!MTB"
        threat_id = "2147783778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoRun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" ascii //weight: 1
        $x_1_2 = "shell\\Search...\\command=My_Music.exe ::{1f4de370-d627-11d1-ba4f-00a0c91eedba}" ascii //weight: 1
        $x_1_3 = "shell\\Delete Viruses" ascii //weight: 1
        $x_1_4 = "IDvDFoldertView" ascii //weight: 1
        $x_1_5 = "I Software" ascii //weight: 1
        $x_1_6 = "Created By D.Ishan Harshana" ascii //weight: 1
        $x_1_7 = "IconArea_Image=IshanBg.ish" ascii //weight: 1
        $x_1_8 = "Photos.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoRun_EC_2147892633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoRun.EC!MTB"
        threat_id = "2147892633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoRun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Backup komputer rumah" wide //weight: 1
        $x_1_2 = "Virus_Bok3p.vbp" wide //weight: 1
        $x_1_3 = "cmd.exe /c start wmplayer.exe" wide //weight: 1
        $x_1_4 = "shutdown -r -f -t 00" wide //weight: 1
        $x_1_5 = "Autorun.inf" wide //weight: 1
        $x_1_6 = "HideFileExt" wide //weight: 1
        $x_1_7 = "W32.Bok3p.A.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoRun_SG_2147894711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoRun.SG!MTB"
        threat_id = "2147894711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoRun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ctfmon.exe" ascii //weight: 1
        $x_1_2 = "down08.3322.org/num.asp" ascii //weight: 1
        $x_1_3 = "\\windows\\currentversion\\RunOnceEx\\ctfmon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

