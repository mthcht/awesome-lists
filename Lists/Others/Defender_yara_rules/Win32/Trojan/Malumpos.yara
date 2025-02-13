rule Trojan_Win32_Malumpos_A_2147696001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malumpos.A"
        threat_id = "2147696001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malumpos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(b|B)[0-9]{13,19}\\^[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\^(1[1-9])((0[1-9])|(1[0-2]))" ascii //weight: 1
        $x_1_2 = {5b 33 2d 39 5d 7b 31 7d 5b 30 2d 39 5d 7b 31 34 2c 31 35 7d 5b 44 3d 5d 28 31 5b 31 2d 39 5d 29 28 28 30 5b 31 2d 39 5d 29 7c 28 31 5b 30 2d 32 5d 29 29 5b 30 2d 39 5d 7b 38 2c 33 30 7d 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

