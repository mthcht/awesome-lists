rule Trojan_Win32_MiniPocket_A_2147926519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniPocket.A!dha"
        threat_id = "2147926519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniPocket"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8b c7 8b d7 8b cf 35 07 18 00 65 81 f2 31 e0 bf 08 81 f1 11 9b 24 15}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

