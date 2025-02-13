rule Trojan_Win32_Bukosonet_A_2147689586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bukosonet.A"
        threat_id = "2147689586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bukosonet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 83 c4 0c 3b f8 76 0c 8a 4c 30 ff 30 0c 30 40 3b c7 72 f4}  //weight: 1, accuracy: High
        $x_1_2 = {50 4f 53 54 00 00 00 00 2f [0-2] 6d [0-2] 2f [0-3] 6d 61 69 6c 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = "<mdb:mork:z" ascii //weight: 1
        $x_1_4 = "Common Files\\System\\wab32.dll" wide //weight: 1
        $x_1_5 = "Thunderbird\\Profiles\\" wide //weight: 1
        $x_1_6 = "eabook.mab" wide //weight: 1
        $x_1_7 = {50 4f 53 54 00 00 00 00 2f 67 72 2d 6d 61 69 6c 2f 65 72 72 2e 70 68 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

