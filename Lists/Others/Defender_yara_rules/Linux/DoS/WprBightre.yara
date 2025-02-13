rule DoS_Linux_WprBightre_D_2147911328_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Linux/WprBightre.D!dha"
        threat_id = "2147911328"
        type = "DoS"
        platform = "Linux: Linux platform"
        family = "WprBightre"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[!] Waiting For  Queue" ascii //weight: 1
        $x_1_2 = "Deleting Disks..." ascii //weight: 1
        $x_1_3 = "DiskName: %s, Deleted: %d - %d" ascii //weight: 1
        $x_1_4 = "[+] Round %d" ascii //weight: 1
        $x_1_5 = "Israel" ascii //weight: 1
        $x_1_6 = "[+] OK, It wasn't ..." ascii //weight: 1
        $x_1_7 = "[+] CPU cores: %d, Threads: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

