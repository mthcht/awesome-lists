rule Trojan_Win32_Serubsit_A_2147644182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Serubsit.A"
        threat_id = "2147644182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Serubsit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0a 42 80 7c 24 10 00 75 0b 8d 59 9f 80 fb 19 77 03 80 c1 e0 0f b6 f0 0f b6 c9 33 f1 c1 e8 08 33}  //weight: 1, accuracy: High
        $x_1_2 = {66 83 7d ac 63 66 83 7d ac 66 66 83 7d ac 23 6a 7b 58 66 89 07}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 51 10 85 c0 78 4c 8b 45 fc 8b 08 50 ff 51 1c 85 c0 78 36 33 ff eb 1f}  //weight: 1, accuracy: High
        $x_1_4 = "?w={user}&s={subd}&site_id={site}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

