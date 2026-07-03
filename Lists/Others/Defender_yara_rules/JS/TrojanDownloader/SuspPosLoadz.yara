rule TrojanDownloader_JS_SuspPosLoadz_Z_2147972899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:JS/SuspPosLoadz.Z!MTB"
        threat_id = "2147972899"
        type = "TrojanDownloader"
        platform = "JS: JavaScript scripts"
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-144] 2e 00 6a 00 73 00 23 01 01 05 09 20 22 27 5c 00}  //weight: 10, accuracy: Low
        $x_10_2 = {77 73 63 72 69 70 74 [0-144] 2e 6a 73 23 01 01 05 09 20 22 27 5c 00}  //weight: 10, accuracy: Low
        $n_10_3 = "ddbf9b05-fcb0-4fce-949e-a6ae899ab273" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

