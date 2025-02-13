rule TrojanDownloader_Java_Rexec_G_2147655204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Rexec.G"
        threat_id = "2147655204"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Rexec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {15 1c a2 1d 1c 64 15 60 05 70 9a 2b 15 5c 33 12 b8 82 91 54}  //weight: 10, accuracy: High
        $x_1_2 = "/io/FileOutputStream" ascii //weight: 1
        $x_1_3 = "getRuntime" ascii //weight: 1
        $x_1_4 = "exec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

