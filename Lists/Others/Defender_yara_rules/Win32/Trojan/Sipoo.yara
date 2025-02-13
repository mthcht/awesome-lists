rule Trojan_Win32_Sipoo_A_2147658515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sipoo.A"
        threat_id = "2147658515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sipoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 58 39 44 24 08 7e ?? 8b 4c 24 04 8a 54 08 ff 30 14 08 40 3b 44 24 08 7c ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 08 ff d6 01 45 0c 39 7d 0c 74 ?? ff 45 10 83 7d ?? ?? 72 ?? 32 c0 eb}  //weight: 1, accuracy: Low
        $x_1_3 = "HostName:%s    Flag:%s" ascii //weight: 1
        $x_1_4 = "BackTime:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

