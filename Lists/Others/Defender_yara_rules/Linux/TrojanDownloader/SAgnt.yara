rule TrojanDownloader_Linux_SAgnt_A_2147825990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/SAgnt.A!xp"
        threat_id = "2147825990"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "killall -9 b26" ascii //weight: 1
        $x_1_2 = {77 67 65 74 20 2d 63 20 2d 50 20 2f 62 69 6e 20 68 74 74 70 3a 2f 2f [0-32] 2f 69 6e 73 74 61 6c 6c 2e 74 61 72}  //weight: 1, accuracy: Low
        $x_1_3 = "tar -xf /bin/install.tar -C /bin/" ascii //weight: 1
        $x_1_4 = "chmod 777 /etc/init.d/taskgrm-" ascii //weight: 1
        $x_1_5 = "ln -s /etc/init.d/taskgrm- /etc/rc.d/rc5.d/taskgrm-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

