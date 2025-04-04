rule HackTool_MacOS_SuspCredDump_A1_2147937941_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspCredDump.A1"
        threat_id = "2147937941"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspCredDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6c 00 61 00 7a 00 61 00 67 00 6e 00 65 00 [0-128] 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspCredDump_B1_2147937942_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspCredDump.B1"
        threat_id = "2147937942"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspCredDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 00 73 00 63 00 6c 00 20 00 2e 00 20 00 72 00 65 00 61 00 64 00 [0-128] 64 00 73 00 41 00 74 00 74 00 72 00 54 00 79 00 70 00 65 00 4e 00 61 00 74 00 69 00 76 00 65 00 3a 00 53 00 68 00 61 00 64 00 6f 00 77 00 48 00 61 00 73 00 68 00 44 00 61 00 74 00 61 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

