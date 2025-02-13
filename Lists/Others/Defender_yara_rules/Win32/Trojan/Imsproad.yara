rule Trojan_Win32_Imsproad_A_2147653746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Imsproad.A"
        threat_id = "2147653746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Imsproad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 6a 24 e8 ?? ?? ff ff 83 c4 08 6a 64 ff 15 ?? ?? ?? 00 6a 02 6a 28 e8 ?? ?? ff ff 83 c4 08 6a 32 ff 15 ?? ?? ?? 00 c7 85 e8 fc ff ff 00 00 00 00 0f b6 8d e3 fc ff ff 85 c9 0f 85 ?? 02 00 00 6a 01 ff 15 ?? ?? ?? 00 83 bd e8 fc ff ff 28 7e}  //weight: 1, accuracy: Low
        $x_1_2 = "stopimspreadevent" ascii //weight: 1
        $x_1_3 = "\\Windows Live\\Messenger\\msnmsgr.exe" ascii //weight: 1
        $x_1_4 = "\\ICQ7.7\\ICQ.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

