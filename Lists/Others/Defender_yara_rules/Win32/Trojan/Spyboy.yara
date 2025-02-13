rule Trojan_Win32_Spyboy_A_2147848166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spyboy.A"
        threat_id = "2147848166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyboy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cr-protect.cybereason.net" ascii //weight: 1
        $x_1_2 = "Lh9qellADyGBYbsNU4DoqVX8E14=" ascii //weight: 1
        $x_1_3 = "go:buildid" ascii //weight: 1
        $x_1_4 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAA" ascii //weight: 1
        $x_1_5 = {48 89 44 24 58 48 89 5c 24 48 48 8b 4c 24 50 48 8b 7c 24 38 48 8b 74 24 40 41 b8 a4 01 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

