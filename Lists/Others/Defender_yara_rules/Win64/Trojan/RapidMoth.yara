rule Trojan_Win64_RapidMoth_A_2147971180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RapidMoth.A"
        threat_id = "2147971180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RapidMoth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "boost::asio::" ascii //weight: 1
        $x_1_2 = {55 6e 6b 6e 6f 77 6e 20 65 72 72 6f 72 20 28 25 64 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 01 c0 47 8d 04 80 41 01 d0 41 83 c0 d0 0f b7 10 48 83 c0 02 66 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

