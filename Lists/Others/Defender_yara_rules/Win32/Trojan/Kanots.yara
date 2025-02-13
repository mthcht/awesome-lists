rule Trojan_Win32_Kanots_A_2147656522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kanots.A"
        threat_id = "2147656522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanots"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c6 74 3e 83 f8 ff 74 39 ff b5 b0 fd ff ff 8d 8d b8 fd ff ff ff b5 b4 fd ff ff 51 50}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 ec 65 78 70 6c c7 45 f0 6f 72 65 72 c7 45 f4 2e 65 78 65 c6 45 f8 00}  //weight: 1, accuracy: High
        $x_1_3 = {56 57 be 8e 02 01 00 56 68 ?? ?? ?? ?? 53}  //weight: 1, accuracy: Low
        $x_1_4 = {ff b5 b4 fd ff ff 51 50 e8 a9 fc ff ff 83 c4 10 85 c0 74 19 68 00 80 00 00 56 ff b5 b4 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

