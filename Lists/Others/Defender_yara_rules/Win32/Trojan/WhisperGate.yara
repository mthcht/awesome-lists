rule Trojan_Win32_Whispergate_J_2147810462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Whispergate.J!dha"
        threat_id = "2147810462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Whispergate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "shutdown -s -f -t " ascii //weight: 10
        $x_10_2 = {c7 04 24 64 50 40 00 e8 b6 25 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Whispergate_RPY_2147844736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Whispergate.RPY!MTB"
        threat_id = "2147844736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Whispergate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "144.217.90.64" ascii //weight: 1
        $x_1_5 = "open.exe" ascii //weight: 1
        $x_1_6 = "Start-Process" ascii //weight: 1
        $x_1_7 = "-WindowStyle Hidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Whispergate_RPX_2147904759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Whispergate.RPX!MTB"
        threat_id = "2147904759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Whispergate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c1 89 d8 ba 00 00 00 00 f7 f1 8b 45 0c 01 d0 0f b6 00 32 45 e7 88 06 83 45 f4 01 8b 45 08 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

