rule Backdoor_Win32_Losfondup_A_2147621032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Losfondup.A"
        threat_id = "2147621032"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Losfondup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {c6 44 24 0c 68 8d 50 1e 89 54 24 0d 66 c7 44 24 11 ff 15 8d 50 16 89 54 24 13 c6 44 24 17 68 33 d2 89 54 24 18 66 c7 44 24 1c ff 15}  //weight: 6, accuracy: High
        $x_3_2 = {8b 55 fc 8a 54 1a ff 80 f2 02 88 54 18 ff 43 4e 75 e6}  //weight: 3, accuracy: High
        $x_3_3 = {c7 45 f8 64 00 00 00 be 00 04 00 00 c7 45 f4 64 00 00 00 bf 00 02 00 00 c7 45 f0 32 00 00 00}  //weight: 3, accuracy: High
        $x_1_4 = "Bot not NAT (Configuration)" ascii //weight: 1
        $x_1_5 = "Bot is NAT (Configuration) not Socks Server" ascii //weight: 1
        $x_1_6 = "No AntiInject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Losfondup_B_2147673421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Losfondup.B"
        threat_id = "2147673421"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Losfondup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af de 81 fb 38 04 00 00 7c b1 81 fb 18 f6 00 00 7f a9}  //weight: 1, accuracy: High
        $x_1_2 = {72 1f 6a 00 6a 00 6a 00 6a 00 6a 00 56 57 53 6a 00 68 00 00 00 02 8d 44 24 30 50 ff 54 24 44 eb 18}  //weight: 1, accuracy: High
        $x_1_3 = {c6 02 e9 2b f0 2b f3 83 ee 05 42 89 32}  //weight: 1, accuracy: High
        $x_1_4 = {bf 28 00 00 00 33 f6 6a 05 e8 ?? ?? ?? ?? 3b ee 0f 84 64 03 00 00 8b c7 e8 ?? ?? ?? ?? 83 f8 28 0f 87 44 03 00 00 ff 24 85}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 fc 9a 02 00 00 6a 00 6a 04 8d 45 fc 50 53 e8}  //weight: 1, accuracy: High
        $x_1_6 = "net localgroup Administrators \"LOCAL SERVlCE\" /add" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Losfondup_C_2147678967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Losfondup.C"
        threat_id = "2147678967"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Losfondup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 1a ff 80 f2 02 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {83 fe 05 7c be 0f af dd 0f af fe 03 df 81 fb b8 88 00 00 7e ae 81 fb 00 71 02 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 23 01 00 00 8d 84 24 24 01 00 00 50 57 8b 03 50 e8 ?? ?? ?? ?? c7 44 24 0c 07 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

