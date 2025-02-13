rule TrojanDownloader_Linux_Chacha_A_2147784138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Chacha.A!MTB"
        threat_id = "2147784138"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Chacha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f [0-32] 3a 38 38 35 32 2f 70 63}  //weight: 1, accuracy: Low
        $x_2_2 = {64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 74 6d 70 2e 6c 00 70 79 74 68 6f 6e 33 2e 4f}  //weight: 2, accuracy: High
        $x_1_3 = "/etc/rc.d/rc%d.d/S90%s" ascii //weight: 1
        $x_1_4 = "/tmp/tmpnam_XXXXXX" ascii //weight: 1
        $x_1_5 = {63 61 73 65 20 24 31 20 69 6e [0-3] 73 74 61 72 74 29 [0-5] 25 73 [0-5] [0-5] 73 74 6f 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

