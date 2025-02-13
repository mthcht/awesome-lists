rule Trojan_Win32_Eyesow_A_2147618644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eyesow.A"
        threat_id = "2147618644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eyesow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\AiSoSo" ascii //weight: 1
        $x_1_2 = "/XQDBHOConfig.aspx?ver=" ascii //weight: 1
        $x_1_3 = "TIdAntiFreeze" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

