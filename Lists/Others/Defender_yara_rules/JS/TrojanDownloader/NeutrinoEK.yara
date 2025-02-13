rule TrojanDownloader_JS_NeutrinoEK_G_2147725837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:JS/NeutrinoEK.gen!G"
        threat_id = "2147725837"
        type = "TrojanDownloader"
        platform = "JS: JavaScript scripts"
        family = "NeutrinoEK"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 2f 00 42 00 20 00 2f 00 2f 00 45 00 3a 00 4a 00 53 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-2] 33 00 32 00 2e 00 74 00 6d 00 70 00 20 00 22 00 [0-32] 22 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 3f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\"Mozilla/5.0 (" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_JS_NeutrinoEK_G_2147725837_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:JS/NeutrinoEK.gen!G"
        threat_id = "2147725837"
        type = "TrojanDownloader"
        platform = "JS: JavaScript scripts"
        family = "NeutrinoEK"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".tmp && start wscript //B //E:JScript " wide //weight: 1
        $x_1_2 = "\" \"Mozilla/5.0 (Windows NT 6.1; " wide //weight: 1
        $x_1_3 = "=\"PE\\x00\\x00\"" wide //weight: 1
        $x_1_4 = "=0;256" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

