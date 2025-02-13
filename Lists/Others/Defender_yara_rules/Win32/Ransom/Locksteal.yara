rule Ransom_Win32_Locksteal_A_2147690430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locksteal.A"
        threat_id = "2147690430"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locksteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/goto/gate.php" wide //weight: 1
        $x_1_2 = ".rans" wide //weight: 1
        $x_1_3 = "Failed to get current hardware profile." wide //weight: 1
        $x_1_4 = "Failed to create desktop for locking." wide //weight: 1
        $x_1_5 = "Crypto + Win Locker" ascii //weight: 1
        $x_1_6 = {3f 00 68 00 77 00 69 00 64 00 3d 00 [0-4] 26 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 3d 00 [0-4] 26 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

