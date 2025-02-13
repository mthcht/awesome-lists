rule Trojan_Win32_BlueStealer_SE_2147850514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlueStealer.SE!MTB"
        threat_id = "2147850514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlueStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f bf c0 89 85 38 fa ff ff db 85 38 fa ff ff dd 9d 30 fa ff ff dd 85 30 fa ff ff 83 3d 00 c0 46 00 00 75 08}  //weight: 1, accuracy: High
        $x_1_2 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_3 = "sendDocument?chat_id=" ascii //weight: 1
        $x_1_4 = "3fbd04f5-b1ed-4060-99b9-fca7ff59c113" ascii //weight: 1
        $x_1_5 = "Shell.Application" ascii //weight: 1
        $x_1_6 = "@RD /S /Q" ascii //weight: 1
        $x_1_7 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*RD_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

