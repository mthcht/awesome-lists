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

