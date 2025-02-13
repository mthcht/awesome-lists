rule Ransom_Win32_Babax_AB_2147765548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Babax.AB!MTB"
        threat_id = "2147765548"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Babax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted by Babax Ransomware!" ascii //weight: 1
        $x_1_2 = "RECOVERY INSTRUCTIONS" ascii //weight: 1
        $x_1_3 = "babaxRansom" ascii //weight: 1
        $x_1_4 = ".babaxed" ascii //weight: 1
        $x_1_5 = "telegramBotToken" ascii //weight: 1
        $x_1_6 = "babaxv2.exe" ascii //weight: 1
        $x_1_7 = "BabaxGang" ascii //weight: 1
        $x_1_8 = "\\BABAX-Stealer\\BabaxStealer v2\\Babax" ascii //weight: 1
        $x_1_9 = "BabaxLocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

