rule Trojan_Win32_GenRansom_STH_2147961269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenRansom.STH"
        threat_id = "2147961269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Files has been exfiltrated" ascii //weight: 1
        $x_1_2 = "Access denied to file" ascii //weight: 1
        $x_1_3 = "IMPORTANT: Keep this information safe and secure. Without it, you cannot decrypt your files." ascii //weight: 1
        $x_1_4 = "Encryption complete." ascii //weight: 1
        $x_1_5 = "Starting encryption on" ascii //weight: 1
        $x_1_6 = "LOCKBIT_SIGNATURE" ascii //weight: 1
        $x_1_7 = "TransferFilesViaFTP" ascii //weight: 1
        $x_1_8 = "AES_BLOCK_SIZE" ascii //weight: 1
        $x_1_9 = "KEY_SIZE" ascii //weight: 1
        $x_1_10 = "FTP Transfer Error:" ascii //weight: 1
        $x_1_11 = "STOR" ascii //weight: 1
        $x_1_12 = "ftp://" ascii //weight: 1
        $x_1_13 = "FtpWebRequest" ascii //weight: 1
        $x_2_14 = "encryption_message.txt" ascii //weight: 2
        $x_5_15 = "email: hackers_lockRansom@protonmail.com" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

