rule Trojan_Win32_Lapsavok_B_2147632870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lapsavok.B"
        threat_id = "2147632870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lapsavok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 e8 03 00 00 99 f7 f9 89 45 f4 8b c7 b9 e8 03 00 00 99 f7 f9 69 c2 e8 03 00 00 89 45 f8 8d 45 f4 50 6a 00 6a 00 8d 85 ec fe ff ff 50 6a 00 e8 ?? ?? ?? ?? 85 c0 7e 5b}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 0b 02 00 00 c7 45 e0 20 4e 00 00 8b 55 ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {74 3b 6a 00 6a 00 68 01 02 00 00 56 e8 ?? ?? ?? ?? 6a 00 6a 00 68 02 02 00 00 56 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 10 56 e8}  //weight: 1, accuracy: Low
        $x_1_4 = "get1.php?sid=" ascii //weight: 1
        $x_1_5 = "inf.php?tp=1&sid=" ascii //weight: 1
        $x_1_6 = "schtasks.exe /create /sc MINUTE /mo 3 /tr \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

