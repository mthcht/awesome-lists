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

rule Trojan_MacOS_SuspAmosExec_B_2147942287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspAmosExec.B"
        threat_id = "2147942287"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspAmosExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "osascript -e" wide //weight: 4
        $x_4_2 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 72 00 20 00 53 00 50 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 44 00 61 00 74 00 61 00 54 00 79 00 70 00 65 00}  //weight: 4, accuracy: Low
        $x_4_3 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 72 00 20 00 53 00 50 00 48 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00 44 00 61 00 74 00 61 00 54 00 79 00 70 00 65 00}  //weight: 4, accuracy: Low
        $x_1_4 = {63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 73 00 [0-16] 51 00 45 00 4d 00 55 00}  //weight: 1, accuracy: Low
        $x_1_5 = {63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 73 00 [0-16] 56 00 4d 00 77 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 73 00 [0-16] 43 00 30 00 37 00 54 00 35 00 30 00 38 00 54 00 47 00 31 00 4a 00 32 00}  //weight: 1, accuracy: Low
        $x_1_7 = {63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 73 00 [0-16] 43 00 30 00 32 00 54 00 4d 00 32 00 5a 00 42 00 48 00 58 00 38 00 37 00}  //weight: 1, accuracy: Low
        $x_4_8 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-16] 65 00 78 00 69 00 74 00 20 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

