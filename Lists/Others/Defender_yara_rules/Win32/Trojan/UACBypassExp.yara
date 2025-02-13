rule Trojan_Win32_UACBypassExp_SA_2147798891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UACBypassExp.SA"
        threat_id = "2147798891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 [0-5] 68 00 6b 00 63 00 75 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 63 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 66 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-16] 20 00 2f 00 64 00 20 00 [0-16] 63 00 6d 00 64 00 [0-16] 20 00 2f 00 63 00 20 00}  //weight: 100, accuracy: Low
        $x_100_2 = {72 65 67 20 61 64 64 [0-5] 68 6b 63 75 5c 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 66 6f 6c 64 65 72 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 [0-16] 20 2f 64 20 [0-16] 63 6d 64 [0-16] 20 2f 63 20}  //weight: 100, accuracy: Low
        $x_100_3 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 [0-5] 68 00 6b 00 63 00 75 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 63 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 73 00 2d 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-16] 20 00 2f 00 64 00 20 00 [0-16] 63 00 6d 00 64 00 [0-16] 20 00 2f 00 63 00 20 00}  //weight: 100, accuracy: Low
        $x_100_4 = {72 65 67 20 61 64 64 [0-5] 68 6b 63 75 5c 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 6d 73 2d 73 65 74 74 69 6e 67 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 [0-16] 20 2f 64 20 [0-16] 63 6d 64 [0-16] 20 2f 63 20}  //weight: 100, accuracy: Low
        $x_1_5 = "wmic" ascii //weight: 1
        $x_1_6 = "rundll32" ascii //weight: 1
        $x_1_7 = "regsvr32" ascii //weight: 1
        $x_1_8 = "powershell" ascii //weight: 1
        $x_1_9 = "cscript" ascii //weight: 1
        $x_1_10 = "wscript" ascii //weight: 1
        $x_1_11 = "schtasks" ascii //weight: 1
        $x_1_12 = "mshta" ascii //weight: 1
        $x_1_13 = "bitsadmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_UACBypassExp_PAGE_2147929633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UACBypassExp.PAGE!MTB"
        threat_id = "2147929633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1}  //weight: 2, accuracy: High
        $x_1_2 = "GenerateGarbageCode" ascii //weight: 1
        $x_2_3 = "EncryptDecryptXOR" ascii //weight: 2
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

