rule Trojan_Win32_PsDownloader_CAZT_2147844071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownloader.CAZT!MTB"
        threat_id = "2147844071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://slasher.ddns.net/download/powershell/Om1hdHRpZmVzdGF0aW9uIGV0dw==" ascii //weight: 1
        $x_1_2 = "LoadWithPartialName" ascii //weight: 1
        $x_1_3 = "Game is now ready to play" ascii //weight: 1
        $x_1_4 = "start /b powershell.exe -nol -w 1 -nop -ep bypass" ascii //weight: 1
        $x_1_5 = "b2eincfile" wide //weight: 1
        $x_1_6 = "launcher.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

