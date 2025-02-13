rule Worm_Win32_Alomim_A_2147622378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Alomim.A"
        threat_id = "2147622378"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Alomim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 83 e9 da d9 ee d9 74 24 f4 5b 81 73 13 89 fa fc a2 83 eb fc e2 f4 75 12 b8 a2 89 fa 77 e7 b5 71 80 a7 f1 fb 13 29 c6 e2 77 fd a9 fb 17 eb 02 ce 77 a3 67 cb 3c 3b 25 7e 3c d6 8e 3b 36 af 88 38 17 56 b2 ae d8 a6 fc 1f 77 fd ad fb 17 c4 02 f6 b7 29 d6 e6 fd 49 02 e6 77 a3 62 73 a0 86 8d 39 cd 62 ed 71 bc 92 0c 3a 84 ae 02 ba f0 29 f9 e6 51 29 e1 f2 17 ab 02 7a 4c a2 89 fa 77 ca b5 a5 cd 54 e9 ac 75 5a 0a 3a 87 f2 e1 0a 76 a6 d6 92 64 5c 03 f4 ab 5d 6e 89 88 c3 fb 8e dc e1 b3 a6 8f c7 fb 8c 8f c7 e7 9e d2 c7 f1 9f fc a2}  //weight: 1, accuracy: High
        $x_1_2 = {41 69 6d 3a 47 4f 49 4d 3f 73 63 72 65 65 6e 6e 61 6d 65 3d [0-16] 26 6d 65 73 73 61 67 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

