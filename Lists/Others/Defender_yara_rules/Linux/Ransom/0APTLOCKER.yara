rule Ransom_Linux_0APTLOCKER_A_2147963212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/0APTLOCKER.A!MSR"
        threat_id = "2147963212"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "0APTLOCKER"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::: 0APT LOCKER :::" ascii //weight: 1
        $x_1_2 = "README0apt.txt" ascii //weight: 1
        $x_1_3 = "embedded_wallpaper.png" ascii //weight: 1
        $x_1_4 = {89 f3 31 f6 31 c9 0f b6 3b 83 c7 d0 83 ff 09 0f 87 4b fe ff ff 89 55 ec 89 f0 ba 0a 00 00 00 01 c9 43 f7 e2 8d 0c 89 89 c6 01 fe 11 d1 8b 55 ec 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_0APTLOCKER_B_2147963495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/0APTLOCKER.B!MSR"
        threat_id = "2147963495"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "0APTLOCKER"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "0APT LOCKER" ascii //weight: 1
        $x_1_2 = "src/bin/encrypt.rs" ascii //weight: 1
        $x_1_3 = "0aptREADME0apt.txt" ascii //weight: 1
        $x_1_4 = "encrypt_with_backend" ascii //weight: 1
        $x_1_5 = {74 74 70 3a 2f 2f 6f 61 70 74 [0-85] 2e 6f 6e 69 6f 6e 2f 6c 6f 67 69 6e 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

