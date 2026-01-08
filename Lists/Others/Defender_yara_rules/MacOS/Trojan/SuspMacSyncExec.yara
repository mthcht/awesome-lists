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
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 6c 00 61 00 37 00 69 00 6e 00 61 00 2e 00 63 00 66 00 64 00 2f 00 [0-16] 2e 00 70 00 68 00 70 00 3f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_SuspMacSyncExec_A_2147960172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspMacSyncExec.A"
        threat_id = "2147960172"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspMacSyncExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6f 00 73 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 2d 00 65 00 20 00 64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-16] 73 00 63 00 72 00 69 00 70 00 74 00 5f 00 70 00 61 00 74 00 68 00 3d 00 [0-48] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00}  //weight: 3, accuracy: Low
        $x_3_2 = {63 00 61 00 74 00 20 00 3e 00 20 00 [0-48] 2f 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 61 00 67 00 65 00 6e 00 74 00 73 00 2f 00 63 00 6f 00 6d 00 2e 00}  //weight: 3, accuracy: Low
        $x_3_3 = "<string>/usr/bin/osascript</string>" wide //weight: 3
        $x_3_4 = "<key>RunAtLoad</key>" wide //weight: 3
        $x_3_5 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-6] 65 00 63 00 68 00 6f 00}  //weight: 3, accuracy: Low
        $x_3_6 = "ImN1cmwgLXMgaHR0cH" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

