rule Ransom_Win32_Cryptscam_2147725256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptscam"
        threat_id = "2147725256"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptscam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "your files have been encryptedi2" ascii //weight: 2
        $x_2_2 = "send 1 BTC to 1F1tAaz5x1HUXrCNLbtMDqcw6o5GN7xX7i" ascii //weight: 2
        $x_2_3 = "The time is over" ascii //weight: 2
        $x_2_4 = "MZ.......................................................!......." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

