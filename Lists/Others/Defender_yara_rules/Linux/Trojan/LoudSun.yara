rule Trojan_Linux_LoudSun_A_2147968512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LoudSun.A!dha"
        threat_id = "2147968512"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LoudSun"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f0 9f 9b a1 ef b8 8f 20 20 e4 bf a1 e5 8f b7 e4 bf 9d e6 8a a4 e5 b7 b2 e5 90 af e7 94 a8 20 2d 20 e4 bd bf e7 94 a8 20 27 6b 69 6c 6c 20 2d 39 20 25 64 27 20 e6 9d a5 e9 80 80 e5 87 ba e7 a8 8b e5 ba 8f}  //weight: 10, accuracy: High
        $x_10_2 = "shadowguard is already running with PID %d" ascii //weight: 10
        $x_10_3 = "/var/run/shadowguard.pid" ascii //weight: 10
        $x_10_4 = {68 00 00 00 00 00 00 00 60 00 00 00 00 00 00 00 57 21 88 77}  //weight: 10, accuracy: High
        $x_10_5 = {08 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 59 e1 a9 7f}  //weight: 10, accuracy: High
        $x_10_6 = {bf 0e 00 00 00 45 31 c0 0f 1f 00 e8}  //weight: 10, accuracy: High
        $x_10_7 = {bf 0d 00 00 00 45 31 c0 0f 1f 44 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

