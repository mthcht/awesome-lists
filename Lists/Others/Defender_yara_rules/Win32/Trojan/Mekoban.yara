rule Trojan_Win32_Mekoban_DB_2147918563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mekoban.DB!MTB"
        threat_id = "2147918563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mekoban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Musquitao\\Desktop\\Load_AutoIT\\ICO\\" ascii //weight: 1
        $x_1_2 = "AnyDesk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

