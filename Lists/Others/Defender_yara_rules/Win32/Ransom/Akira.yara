rule Ransom_Win32_Akira_A_2147847316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Akira.A!ibt"
        threat_id = "2147847316"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "the internal infrastructure of your company is fully or partially dead, all your backups" ascii //weight: 10
        $x_1_2 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "Keep in mind that the faster you will get in touch, the less damage we cause." ascii //weight: 1
        $x_1_4 = "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\"" ascii //weight: 1
        $x_1_5 = "D:\\vcprojects\\akira\\asio" ascii //weight: 1
        $x_1_6 = {68 74 74 70 73 3a 2f 2f 61 6b 69 72 61 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-21] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Akira_B_2147907860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Akira.B!ibt"
        threat_id = "2147907860"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "akira_readme.txt" ascii //weight: 4
        $x_1_2 = {2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 33 00 00 00 00 00 00 00 00 00 2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 00 00 2e 00 73 00 71 00 6c 00 00 00 00 00 00 00 00 00 2e 00 73 00 70 00 71 00 00 00 00 00 00 00 00 00 2e 00 74 00 6d 00 64 00 00 00 00 00 00 00 00 00 2e 00 74 00 65 00 6d 00 78}  //weight: 1, accuracy: High
        $x_1_3 = {61 00 63 00 63 00 64 00 63 00 00 00 00 00 2e 00 61 00 63 00 63 00 64 00 62 00 00 00 00 00 2e 00 34 00 64 00 6c 00 00 00 00 00 00 00 00 00 2e 00 34 00 64 00 64 00 00 00 00 00 00 00 00 00 2e 00 61 00 63 00 63 00 66 00 74 00 00 00 00 00 2e 00 61 00 63 00 63 00 64 00 74}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 64 00 62 00 63 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 33 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 2d 00 77 00 61 00 6c 00 00 00 2e 00 64 00 62 00 2d 00 73 00 68 00 6d 00 00 00 2e 00 64 00 62 00 76 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 74 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 73 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Akira_DA_2147960654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Akira.DA!MTB"
        threat_id = "2147960654"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "akira_readme.txt" ascii //weight: 10
        $x_10_2 = ".akira" ascii //weight: 10
        $x_1_3 = "Cipher dont start!" ascii //weight: 1
        $x_1_4 = "Decrypt exception:" ascii //weight: 1
        $x_1_5 = "--encryption_path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Akira_Z_2147960655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Akira.Z!MTB"
        threat_id = "2147960655"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "akira_readme.txt" ascii //weight: 1
        $x_1_2 = "Number of threads to encrypt =" ascii //weight: 1
        $x_1_3 = "write_encrypt_info error:" ascii //weight: 1
        $x_1_4 = "Log-%d-%m-%Y-%H-%M-%S" ascii //weight: 1
        $x_1_5 = "--encryption_path" ascii //weight: 1
        $x_1_6 = "--encryption_percent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Akira_ZA_2147960656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Akira.ZA!MTB"
        threat_id = "2147960656"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 0f 57 c0 89 44 24 18 8b 45 0c 89 44 24 1c 8d 44 24 10 50 8d 44 24 08 66 0f 13 44 24 14 50 51 52 ff 36 c7 44 24 34 00 00 00 00 c7 44 24 18 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 0e 84 c0 0f 84 e2 01 00 00 88 85 54 ff ff ff 0f b6 44 0e 01 88 85 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

