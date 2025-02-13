rule Ransom_Win32_Bosloki_A_2147726220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bosloki.A"
        threat_id = "2147726220"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bosloki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%APPDATA%\\Readerpdf\\Adobe.exe" ascii //weight: 10
        $x_10_2 = "All files have been decrypted" ascii //weight: 10
        $x_5_3 = "loris Attack is Already Running on" ascii //weight: 5
        $x_1_4 = "learn how to pay us https://www.youtube.com/watch?v=" ascii //weight: 1
        $x_1_5 = "em back, Just pay us" ascii //weight: 1
        $x_1_6 = "BotKillers" ascii //weight: 1
        $x_2_7 = "ddos.slowloris.stop" ascii //weight: 2
        $x_1_8 = "Decrypt_File" ascii //weight: 1
        $x_2_9 = "The stub has no BTC address " ascii //weight: 2
        $x_2_10 = "Launch_crypt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Bosloki_B_2147726227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bosloki.B"
        threat_id = "2147726227"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bosloki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c0 53 33 d2 ?? 8d 0c 02 8a 09 ?? ?? 80 f1 ad 8d 1c 02 88 0b 42 81 fa ?? ?? ?? ?? 75 ?? 05 ?? ?? ?? ?? 5b c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

