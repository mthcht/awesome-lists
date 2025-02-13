rule Trojan_Win32_Aphidma_A_2147598669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aphidma.A"
        threat_id = "2147598669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aphidma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 68 f5 1f 00 00 8d 85 a7 de ff ff 50 8b 45 f8 50 e8 ?? ?? ff ff 89 45 ec 83 7d ec 00 74}  //weight: 2, accuracy: Low
        $x_1_2 = {66 ba bb 01 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 83 f8 ff 75 34 66 ba bb 01}  //weight: 1, accuracy: Low
        $x_1_3 = {66 ba 50 00 b8 ?? ?? 40 00 e8 ?? ?? ff ff 83 f8 ff 75 34 66 ba 50 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Aphidma_B_2147605629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aphidma.B"
        threat_id = "2147605629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aphidma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "209.160.21.76" ascii //weight: 10
        $x_1_2 = "kolorodiumsen.com" ascii //weight: 1
        $x_1_3 = "interfiumsen.com" ascii //weight: 1
        $x_1_4 = "kricketploies.com" ascii //weight: 1
        $x_10_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\csfdll" ascii //weight: 10
        $x_10_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\crypt32set" ascii //weight: 10
        $x_10_7 = "I am Installed" ascii //weight: 10
        $x_10_8 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

