rule Trojan_JS_Obfus_AK_2147747833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:JS/Obfus.AK!eml"
        threat_id = "2147747833"
        type = "Trojan"
        platform = "JS: JavaScript scripts"
        family = "Obfus"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Application.StartupPath" ascii //weight: 1
        $x_1_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 20 26 20 22 57 53 63 22 20 26 20 00 20 26 20 22 72 22 20 26 20 22 22 20 26 20 22 69 70 22 20 26 20 00 20 26 20 22 74 2e 22 20 26 20}  //weight: 1, accuracy: Low
        $x_1_3 = "\"Run\", VbMethod, _" ascii //weight: 1
        $x_1_4 = {26 20 46 76 42 65 72 5f 36 35 20 26 20 22 6a 22 20 26 20 46 76 42 65 72 5f 36 35 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22 20 26 20 46 76 42 65 72 5f 36 35 56 00 26 20 45 6d 70 74 79 20 26 20 22 [0-15] 2e 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = "FvBer_65 & \"s\" & FvBer_65 & \"h\" & FvBer_65 & \"el\" & FvBer_65 & \"l\" & Empty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

