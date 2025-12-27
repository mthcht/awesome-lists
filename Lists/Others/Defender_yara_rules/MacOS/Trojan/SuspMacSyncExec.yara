rule Trojan_MacOS_SuspMacSyncExec_B_2147960131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspMacSyncExec.B"
        threat_id = "2147960131"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspMacSyncExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = "curl -s" wide //weight: 6
        $x_1_2 = "https://t.me/phefuckxiabot | sed -n" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6b 00 79 00 73 00 2e 00 6c 00 69 00 2f 00 [0-16] 2e 00 70 00 68 00 70 00 3f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6b 00 79 00 73 00 2e 00 63 00 78 00 2f 00 [0-16] 2e 00 70 00 68 00 70 00 3f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

