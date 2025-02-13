rule Trojan_Linux_ZHTrap_A_2147796612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ZHTrap.A!xp"
        threat_id = "2147796612"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ZHTrap"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox ZHTRAP" ascii //weight: 1
        $x_1_2 = "ZoneSec" ascii //weight: 1
        $x_1_3 = "QjfjxSRDFGSFDdf" ascii //weight: 1
        $x_1_4 = "t0talc0ntr0l4" ascii //weight: 1
        $x_1_5 = "hacktheworld1337" ascii //weight: 1
        $x_1_6 = {b0 80 9f e5 98 31 82 e0 a2 23 a0 e1 02 34 a0 e1 03 30 62 e0 01 10 63 e0 01 10 20 e0 0c 30 8e e0 01 c0 8c e2 01 30 23 e0 0a 00 5c e1 06 30 c4 e7 01 50 87 e2 00 e0 a0 e3 0c 40 a0 e1 0f 00 00 0a 6c 10 9f e5 00 20 91 e5 02 00 d7 e7 98 20 83 e0 a3 33 a0 e1 03 24 a0 e1 06 10 d4 e7 02 20 63 e0 00 00 62 e0 00 10 21 e0 ff 00 01 e2 0e 00 55 e3 06 00 c4 e7 0e 70 a0 e1 df ff ff ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_ZHTrap_B_2147796613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ZHTrap.B!xp"
        threat_id = "2147796613"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ZHTrap"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /sfkjdkfdj.txt" ascii //weight: 1
        $x_1_2 = "ZoneSec" ascii //weight: 1
        $x_1_3 = "QjfjxSRDFGSFDdf" ascii //weight: 1
        $x_1_4 = "hacktheworld1337" ascii //weight: 1
        $x_1_5 = "0xdeadbeef.tw" ascii //weight: 1
        $x_1_6 = {0f be ca ba 81 80 80 80 89 c8 f7 ea 89 c8 c1 f8 1f 01 ca c1 fa 07 29 c2 89 d0 c1 e0 08 29 d0 89 f2 29 c1 46 8b 44 24 28 30 cb 00 54 24 27 32 5c 24 26 32 5c 24 27 39 74 24 14 88 1c 28 74 21 8b 44 24 20 89 74 24 28 0f b6 1c 2e 0f b6 14 07 8d 47 01 31 ff 83 f8 0e c6 44 24 27 00 7f a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

