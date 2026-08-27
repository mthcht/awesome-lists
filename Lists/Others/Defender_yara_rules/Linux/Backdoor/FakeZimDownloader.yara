rule Backdoor_Linux_FakeZimDownloader_A_2147977113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/FakeZimDownloader.A"
        threat_id = "2147977113"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "FakeZimDownloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "0 3 * * * /dev/stdin" ascii //weight: 4
        $x_3_2 = "%s root cron write suc %s" ascii //weight: 3
        $x_3_3 = "%s SSH key add suc %s" ascii //weight: 3
        $x_2_4 = "transzimbra.linkpc.net/get/zimclient" ascii //weight: 2
        $x_2_5 = "wslogzimbra.linkpc.net/wsstat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

