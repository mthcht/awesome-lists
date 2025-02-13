rule Trojan_Win32_Dowque_A_2147582007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dowque.A"
        threat_id = "2147582007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dowque"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff ff 8b d8 83 fb ff 0f 84 ?? ?? 00 00 6a 02 6a 00 6a fc 53 e8}  //weight: 3, accuracy: Low
        $x_3_2 = {6a 00 8d 45 f8 50 6a 04 8d 45 f4 50 53 e8 ?? ?? ?? ff 81 75}  //weight: 3, accuracy: Low
        $x_3_3 = {8b d8 83 fb 01 7c 66 8d 45 f0 50 8b cb 49 ba 01 00 00 00 8b 45 ec}  //weight: 3, accuracy: High
        $x_1_4 = "{A6011F8F-A7F8-49AA-9ADA-49127D43138F}" ascii //weight: 1
        $x_1_5 = "Files\\Microsoft Shared\\MSINFO" ascii //weight: 1
        $x_1_6 = "HTTP/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dowque_B_2147596462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dowque.B"
        threat_id = "2147596462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dowque"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 81 c4 fc fe ff ff 53 33 d2 89 95 fc fe ff ff 8b d8 33 c0 55 68 2e 49 40 00 64 ff 30 64 89 20 68 ff 00 00 00 8d 85 00 ff ff ff 50 e8 69 fc ff ff 85 c0 75 07 c6 85 00 ff ff ff 43 8a 85 00 ff ff ff 50 e8 d2 fc ff ff 83 f8 01 1b c0 40 84 c0 75 07 c6 85 00 ff ff ff 43 8d 85 fc fe ff ff 8a 95 00 ff ff ff e8 40 f4 ff ff 8b 95 fc fe ff ff 8b c3 b9 43 49 40 00 e8 d2 f4 ff ff 33 c0 5a 59 59 64 89 10 68 35 49 40 00 8d 85 fc fe ff ff e8 f6 f2 ff ff c3 e9 64 ed ff ff eb ed 5b 8b e5 5d c3}  //weight: 10, accuracy: High
        $x_2_2 = "CLSID\\{2A3ECF1D-285A-463E-8173-7D052C8FA270}" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 2
        $x_1_4 = "mutouexemutex" ascii //weight: 1
        $x_1_5 = ":\\Program Files\\Outlook Express" ascii //weight: 1
        $x_1_6 = "mutouDLLmutext" ascii //weight: 1
        $x_1_7 = "mutouFileMap" ascii //weight: 1
        $x_1_8 = "GetMsgHookOn" ascii //weight: 1
        $x_1_9 = "delself.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

