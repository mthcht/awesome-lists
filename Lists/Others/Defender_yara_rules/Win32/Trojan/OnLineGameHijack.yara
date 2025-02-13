rule Trojan_Win32_OnLineGameHijack_2147743661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OnLineGameHijack!ibt"
        threat_id = "2147743661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGameHijack"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{B8592103-AE8C-4D37-807F-F1CB76E62B7C}" ascii //weight: 1
        $x_1_2 = {ff 15 00 41 0e 10 8b f8 85 ff 74 6b 6a 04 68 00 30 00 00 ff b5 5c f2 ff ff 6a 00 53 ff 15 44 40 0e 10 8b f0 85 f6 74 49 83 bd 60 f2 ff ff 10 8d 8d 4c f2 ff ff 6a 00 ff b5 5c f2 ff ff 0f 43 8d 4c f2 ff ff 51 56 53 ff 15 48 40 0e 10 85 c0 74 20 6a 00 6a 00 56 57 6a 00 6a 00 53 ff 15 4c 40 0e 10 8b 35 ec 40 0e 10 85 c0 74 0b 50 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

