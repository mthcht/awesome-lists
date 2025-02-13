rule Trojan_Win32_Qimiral_A_2147630923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qimiral.A"
        threat_id = "2147630923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qimiral"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM icq.exe" ascii //weight: 1
        $x_1_2 = "monitor?sid=" ascii //weight: 1
        $x_1_3 = {48 31 4e 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 6a 04 8d 45 f4 50 68 40 78 6b 00 56 e8}  //weight: 1, accuracy: High
        $x_1_5 = {8a 45 ff 04 e0 2c 5f 72 06 04 bf 2c 40 73 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

