rule Trojan_Linux_ChocoPoc_B_2147974283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ChocoPoc.B!AMTB"
        threat_id = "2147974283"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ChocoPoc"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 31 c0 4c 8d ac 24 10 01 00 00 45 31 c9 49 f7 f4 48 89 c6 66 2e 0f 1f 84 00 00 00 00 00 44 31 c6 31 d2 89 f1 89 f0 c0 e8 05 c1 e1 02 09 c1 49 8d 41 01 49 f7 f4 0f b6 44 15 00 42 32 44 0d 00 31 d2 89 c6 43 32 44 05 00 31 c8 31 ce 43 88 44 05 00 4c 89 c0 49 83 c0 01 83 e0 07 49 8d 44 01 0d 49 f7 f4 49 89 d1 49 83 f8 10 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

