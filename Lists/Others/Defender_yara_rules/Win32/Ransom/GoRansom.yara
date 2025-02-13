rule Ransom_Win32_GoRansom_G_2147744749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GoRansom.G!MTB"
        threat_id = "2147744749"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GoRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files have been encrypted by The GoRansom POC Ransomware" ascii //weight: 1
        $x_1_2 = "Decryption Key is hardcoded in the binary" ascii //weight: 1
        $x_1_3 = "Uses XOR encryption with an 8bit (byte) key" ascii //weight: 1
        $x_1_4 = "Only 255 possible keys" ascii //weight: 1
        $x_1_5 = "Run the ransomware in the command line with one argument, decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

