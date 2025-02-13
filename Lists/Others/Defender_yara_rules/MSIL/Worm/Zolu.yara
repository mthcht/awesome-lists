rule Worm_MSIL_Zolu_A_2147709098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Zolu.A"
        threat_id = "2147709098"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zolu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "uloz botnet.exe" ascii //weight: 1
        $x_1_2 = {2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 3f 00 68 00 77 00 69 00 64 00 3d 00 [0-32] 6c 00 6f 00 61 00 64 00 2e 00 65 00 78 00 65 00 [0-4] 2f 00 6e 00 61 00 6d 00 65 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 62 00 6f 00 74 00 [0-4] 5c 00 53 00 68 00 72 00 6f 00 6f 00 6d 00 4f 00 66 00 44 00 6f 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 [0-4] 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 [0-4] 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 49 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

