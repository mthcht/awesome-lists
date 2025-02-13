rule TrojanDownloader_Linux_Korkerds_A_2147822866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Korkerds.A!xp"
        threat_id = "2147822866"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Korkerds"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sed -i '$d' /etc/crontab" ascii //weight: 1
        $x_1_2 = "chmod +x /bin/httpdns" ascii //weight: 1
        $x_1_3 = "nohup /bin/sh /bin/httpdns" ascii //weight: 1
        $x_1_4 = {2f 72 61 77 2f [0-16] 2d 6f 20 2f 62 69 6e 2f 68 74 74 70 64 6e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

