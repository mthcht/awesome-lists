rule Trojan_Win32_ButeRat_MA_2147823661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ButeRat.MA!MTB"
        threat_id = "2147823661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ButeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 03 58 57 6a 02 50 57 57 68 00 00 00 c0 8d ?? ?? ?? ?? ff 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 fc 50 6a 01 6a 00 bb ?? ?? ?? ?? 53 68 01 00 00 80 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = "InternetSetPerSiteCookieDecisionW" ascii //weight: 1
        $x_1_4 = "\\INTERNAL\\REMOTE.EXE" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

