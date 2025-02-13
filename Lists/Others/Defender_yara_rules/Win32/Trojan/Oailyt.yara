rule Trojan_Win32_Oailyt_A_2147617671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oailyt.A"
        threat_id = "2147617671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oailyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 54 44 6f 77 6e 46 69 6c 65 54 68 72 65 61 64 8b c0 55 8b ec 51}  //weight: 1, accuracy: High
        $x_1_2 = {20 bf aa bb fa ca b1 bc e4 3a 20 00 ff ff ff ff 07 00 00 00 20 b3 a7 c9 cc a3 ba 00 ff ff ff ff 03 00 00 00 3c 44 3e 00 ff ff ff ff 07 00 00 00 56 69 70 31 2e 35 32 00}  //weight: 1, accuracy: High
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

