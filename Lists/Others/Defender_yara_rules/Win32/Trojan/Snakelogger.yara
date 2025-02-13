rule Trojan_Win32_Snakelogger_SWA_2147931285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snakelogger.SWA!MTB"
        threat_id = "2147931285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "qualityrespond.exe" ascii //weight: 2
        $x_1_2 = "wextract.pdb" ascii //weight: 1
        $x_1_3 = "Command.com /c %s" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

