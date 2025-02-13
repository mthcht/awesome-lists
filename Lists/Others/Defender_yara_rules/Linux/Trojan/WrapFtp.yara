rule Trojan_Linux_WrapFtp_A_2147824649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/WrapFtp.A!xp"
        threat_id = "2147824649"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "WrapFtp"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/netrcbak" ascii //weight: 1
        $x_1_2 = "/home/hoge/.netrc" ascii //weight: 1
        $x_1_3 = "chmod go-rwx %s" ascii //weight: 1
        $x_1_4 = "FTP server ready" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

