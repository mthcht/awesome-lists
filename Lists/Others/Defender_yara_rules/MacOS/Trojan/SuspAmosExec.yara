rule Trojan_MacOS_SuspAmosExec_A_2147939331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspAmosExec.A"
        threat_id = "2147939331"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspAmosExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "osascript -e" wide //weight: 1
        $x_1_2 = "list disks" wide //weight: 1
        $x_1_3 = {73 00 65 00 74 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 50 00 61 00 74 00 68 00 20 00 74 00 6f 00 [0-16] 2f 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 73 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 65 00 74 00 20 00 61 00 70 00 70 00 4e 00 61 00 6d 00 65 00 20 00 74 00 6f 00 [0-16] 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 72 00 6d 00 20 00 2d 00 66 00}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 63 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 78 00 61 00 74 00 74 00 72 00 20 00 2d 00 63 00}  //weight: 1, accuracy: Low
        $x_1_8 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 63 00 68 00 6d 00 6f 00 64 00 20 00 2b 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SuspAmosExec_D_2147941335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspAmosExec.D"
        threat_id = "2147941335"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspAmosExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "osascript -e" wide //weight: 1
        $x_1_2 = "jackiemac" wide //weight: 1
        $x_1_3 = "maria" wide //weight: 1
        $x_1_4 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 6d 00 6b 00 64 00 69 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = "cat " wide //weight: 1
        $x_1_6 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 66 00 69 00 6c 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_7 = "market-history-cache.json" wide //weight: 1
        $x_1_8 = ".DS_Store" wide //weight: 1
        $x_1_9 = "list folder" wide //weight: 1
        $x_1_10 = "POSIX file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

