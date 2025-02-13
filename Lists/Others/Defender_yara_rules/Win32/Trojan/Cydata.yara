rule Trojan_Win32_Cydata_A_2147722400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cydata.A"
        threat_id = "2147722400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cydata"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ct_init: length != 256" ascii //weight: 10
        $x_10_2 = "ct_init: 256+dist != 512" ascii //weight: 10
        $x_1_3 = "https://cbi.hanyang.ac.kr/skin/page/board.asp" ascii //weight: 1
        $x_1_4 = "https://www.asps.co.kr/media/view.asp" ascii //weight: 1
        $x_10_5 = {8b 5d f8 53 e8 ?? ?? ?? ?? 8b f0 83 c4 04 85 f6 74 26 8b c3 8d 50 01 8d a4 24 00 00 00 00 8a 08 40 84 c9 75 f9 2b c2 50 56 53 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 10 33 f6 8d 64 24 00 53 ff 15 ?? ?? ?? ?? 8b f8 85 ff 75 08 6a 64 ff 15 ?? ?? ?? ?? 46 85 ff 75 05 83 fe 04 7c e1 33 db 8b 4d fc 51 57 ff 15 ?? ?? ?? ?? 8b f0 85 f6 75 08 6a 64 ff 15 ?? ?? ?? ?? 43 85 f6 75 05 83 fb 04 7c dd 8b 55 fc 52 e8 ?? ?? ?? ?? 8b 45 f8 50 e8 ?? ?? ?? ?? 8b 7d f4 83 c4 08 89 77 04 5f 8b c6 5e 5b 8b e5 5d c3 85 c0 74 09 50 e8 ?? ?? ?? ?? 83 c4 04 33 f6 89 77 04 8b 47 04 5f 5e 5b 8b e5 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

