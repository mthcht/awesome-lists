rule Trojan_Win32_Fnvhack_A_2147626264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fnvhack.A"
        threat_id = "2147626264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fnvhack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 00 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_10_2 = {6a 4a 59 d9 ee d9 74 24 f4 58 81 70 13 fb ee 99 bc 83 e8 fc e2 f4}  //weight: 10, accuracy: High
        $x_1_3 = {31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 40 08 5e 68 8e 4e 0e ec 50 ff d6}  //weight: 1, accuracy: High
        $x_1_4 = {8d 20 8a 12 ff cb 65 d9 b0 70 9e 85 11 70 ae 91 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

