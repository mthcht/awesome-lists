rule Trojan_Win32_Pinchduke_A_2147893260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pinchduke.A!MTB"
        threat_id = "2147893260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pinchduke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subdom.dom.com" ascii //weight: 1
        $x_1_2 = "Software\\Mail.Ru\\Agent\\mra_logins" ascii //weight: 1
        $x_1_3 = "%USERPROFILE%\\Application Data\\SmartFTP\\Client 2.0\\Favorites" ascii //weight: 1
        $x_1_4 = "leskz_20100414" ascii //weight: 1
        $x_1_5 = "pipe\\systemflagsemafore" ascii //weight: 1
        $x_1_6 = "Software\\Mail.Ru\\Agent\\magent_logins" ascii //weight: 1
        $x_1_7 = "\"%TEMP%\\smss.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

