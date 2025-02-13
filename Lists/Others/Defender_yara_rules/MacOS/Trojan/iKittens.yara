rule Trojan_MacOS_iKittens_A_2147745418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/iKittens.A!MTB"
        threat_id = "2147745418"
        type = "Trojan"
        platform = "MacOS: "
        family = "iKittens"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/MacDownloader/MyApp3/" ascii //weight: 2
        $x_1_2 = "/Adware Removal Tool.build/Debug/Adware Removal Tool.build/" ascii //weight: 1
        $x_1_3 = "/etc/kcbackup.cfg /Library/Keychains/" ascii //weight: 1
        $x_1_4 = "/tmp/mastering-vim.pdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

