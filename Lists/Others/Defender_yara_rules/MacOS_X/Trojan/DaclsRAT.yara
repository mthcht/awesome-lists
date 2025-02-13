rule Trojan_MacOS_X_DaclsRAT_A_2147754803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS_X/DaclsRAT.A!dha"
        threat_id = "2147754803"
        type = "Trojan"
        platform = "MacOS_X: "
        family = "DaclsRAT"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "01/images.tgz.001 > /dev/null 2>&1 && chmod +x ~/Library/.mina > /dev/null 2>&1 " ascii //weight: 1
        $x_1_2 = {a0 d2 89 29 27 78 75 f6 aa 78 c7 98 39 a0 05 ed 39 18 82 62 33 ea 18 bb 18 30 78 97 a9 e1 8a 92}  //weight: 1, accuracy: High
        $x_1_3 = {63 68 65 63 6b 00 7b 22 72 65 73 75 6c 74 22 3a 22 6f 6b 22 7d 00 73 61 76 65 00 73 65 73 73 69 6f 6e 5f 69 64 00 76 61 6c 75 65 00 25 59 2d 25 6d 2d 25 64 20 25 58 00 53 43 41 4e 09 25 73 09 25 64 2e 25 64 2e 25 64 2e 25 64 09 25 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

