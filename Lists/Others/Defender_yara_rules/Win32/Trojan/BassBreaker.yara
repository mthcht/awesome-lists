rule Trojan_Win32_BassBreaker_A_2147818409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BassBreaker.A!dha"
        threat_id = "2147818409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BassBreaker"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\..\\Management.dll" wide //weight: 1
        $x_1_2 = "\\..\\LoggingPlatform.dll" wide //weight: 1
        $x_1_3 = "\\..\\config\\Config.dat" wide //weight: 1
        $x_1_4 = "\\FileCoAuth.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BassBreaker_B_2147822378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BassBreaker.B!dha"
        threat_id = "2147822378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BassBreaker"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "021347106042145" ascii //weight: 1
        $x_1_2 = {6a 30 8d 85 8c fe ff ff b9 c4 5c 08 10 50 e8 05 49 00 00 6a 32 8d 8d a4 fe ff ff c7 45 fc 00 00 00 00 51 8b c8 e8 ee 48 00 00 6a 31 8d 8d bc fe ff ff c6 45 fc 01 51 8b c8 e8 da 48 00 00 6a 33 8d 8d d4 fe ff ff c6 45 fc 02 51 8b c8 e8 c6 48 00 00 6a 34 8d 8d ec fe ff ff c6 45 fc 03 51 8b c8 e8 b2 48 00 00 6a 37 8d 8d 04 ff ff ff c6 45 fc 04 51 8b c8 e8 9e 48 00 00 6a 31 8d 8d 1c ff ff ff c6 45 fc 05 51 8b c8 e8 8a 48 00 00 6a 30 8d 8d 34 ff ff ff c6 45 fc 06 51 8b c8 e8 76 48 00 00 6a 36 8d 8d 4c ff ff ff c6 45 fc 07 51 8b c8 e8 62 48 00 00 6a 30 8d 8d 64 ff ff ff c6 45 fc 08 51 8b c8 e8 4e 48 00 00 6a 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

