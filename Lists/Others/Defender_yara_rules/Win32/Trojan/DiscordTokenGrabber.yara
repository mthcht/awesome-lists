rule Trojan_Win32_DiscordTokenGrabber_DA_2147976562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiscordTokenGrabber.DA!MTB"
        threat_id = "2147976562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiscordTokenGrabber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 0e c0 07 5d 0e bc 07 43 0e c0 07 65 0e bc 07 43 0e c0 07 65 0e bc 07 43 0e c0 07 65 0e bc 07 43 0e c0 07 65 0e bc 07 43 0e c0 07 6d 0e bc 07 43 0e c0 07 02 46 0e ac 07 43 0e c0 07 5f 0e b8 07 43 0e c0 07 5d 0e bc 07 43 0e c0}  //weight: 1, accuracy: High
        $x_1_2 = {01 d7 83 d5 00 eb 3f 90 31 c9 80 63 01 f9 66 89 4b 32 0f be ca 83 ea 01 0f b7 4c 4b 46 88 53 44 0f be d2 8b 54 93 78 8b 40 48 66 89 4b 46 89 53 74 e8 b2 c6 fc ff 8b 43 74 0f b7 4b 46 0f b7 50}  //weight: 1, accuracy: High
        $x_1_3 = {20 59 f8 b6 f6 62 91 dd fe 76 12 0e d3 85 d8 a4 2a f7 14 c9 81 28 92 dc e1 76 c4 39 5b da 31 9d 56 ea 6b a8 87 1d 5d d5 03 8d b2 da d3 c4 31 67 90 c5 9a b9 f0 b1 5d a0 e0 75 b0 8d 2e ae 2a 9f}  //weight: 1, accuracy: High
        $x_1_4 = {c5 0e 04 44 0b 4b 0e dc 40 43 0e e0 40 45 0e dc 40 43 0e e0 40 4d 0e dc 40 43 0e e0 40 02 51 0e c4 40 43 0e e0 40 02 47 0e cc 40 43 0e e0 40 69 0e cc 40 43 0e e0 40 4f 0e dc 40 43 0e e0 40 45 0e dc 40 48 0e e0 40 4e 0e dc 40 43 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

