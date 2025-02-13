rule Trojan_Win32_Wilbot_AS_2147789251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wilbot.AS!MTB"
        threat_id = "2147789251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wilbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "interest\\will.pdb" ascii //weight: 3
        $x_3_2 = "Fruitpitch" ascii //weight: 3
        $x_3_3 = "Govern" ascii //weight: 3
        $x_3_4 = "Sonspell" ascii //weight: 3
        $x_3_5 = "GetTempPathW" ascii //weight: 3
        $x_3_6 = "FindFirstFileExW" ascii //weight: 3
        $x_3_7 = "GetUserDefaultLocaleName" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

