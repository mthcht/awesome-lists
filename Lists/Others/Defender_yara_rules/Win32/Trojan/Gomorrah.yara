rule Trojan_Win32_Gomorrah_RPX_2147892949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gomorrah.RPX!MTB"
        threat_id = "2147892949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gomorrah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileZillaStealer" ascii //weight: 1
        $x_1_2 = "CookieslineCount" ascii //weight: 1
        $x_1_3 = "contact_bot" ascii //weight: 1
        $x_1_4 = "KeyLogs" ascii //weight: 1
        $x_1_5 = "upload_screenshot_c2" ascii //weight: 1
        $x_1_6 = "keylog_txt" ascii //weight: 1
        $x_1_7 = "GetOutlookPasswords" ascii //weight: 1
        $x_1_8 = "gate.php" wide //weight: 1
        $x_1_9 = "Cookies_Chrome.txt" wide //weight: 1
        $x_1_10 = "credit_cards" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

