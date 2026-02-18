rule Trojan_Win32_Mimic_LM_2147963273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mimic.LM!MTB"
        threat_id = "2147963273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "171"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decrypt tool" ascii //weight: 1
        $x_2_2 = "MIMIC_LOG.txt" ascii //weight: 2
        $x_3_3 = "MIMIC_DECRYPT.txt" ascii //weight: 3
        $x_4_4 = "YourBunnyWrote" ascii //weight: 4
        $x_5_5 = "CLONE INFO: I'm a clone!" ascii //weight: 5
        $x_6_6 = "CLONE INFO: I'm original process!" ascii //weight: 6
        $x_7_7 = "This file was encrypted with another key or not encrypted ever" ascii //weight: 7
        $x_8_8 = "Cannot decrypt file after encryptor version" ascii //weight: 8
        $x_9_9 = "Decryption finished." ascii //weight: 9
        $x_10_10 = "System should be rebooted in 30 seconds..." ascii //weight: 10
        $x_11_11 = "Secret key found:" ascii //weight: 11
        $x_12_12 = "hashlist.txt" ascii //weight: 12
        $x_13_13 = "md5_check.txt" ascii //weight: 13
        $x_14_14 = "Remove debugger..." ascii //weight: 14
        $x_15_15 = "Kill Cryptor..." ascii //weight: 15
        $x_16_16 = "Delete session key..." ascii //weight: 16
        $x_17_17 = "Restore Services..." ascii //weight: 17
        $x_18_18 = "Restore Processes..." ascii //weight: 18
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

