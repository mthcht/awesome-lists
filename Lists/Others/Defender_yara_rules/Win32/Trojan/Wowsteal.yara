rule Trojan_Win32_Wowsteal_Y_2147596536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wowsteal.Y"
        threat_id = "2147596536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 43 4f 4d 53 50 45 43 00 2f 63 20 64 65 6c 20 00 20 3e 20 6e 75 6c 00 00 4f 70 65 6e 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 77 6f 6f 6f 6c 2e 64 61 74}  //weight: 10, accuracy: High
        $x_10_3 = "\\map\\88X600.nmp" ascii //weight: 10
        $x_1_4 = "ftyou" ascii //weight: 1
        $x_1_5 = "Shanda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

