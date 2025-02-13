rule VirTool_Win32_Runcrypt_D_2147617124_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Runcrypt.D"
        threat_id = "2147617124"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Runcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 64 52 63 34 00 00 4d 6f 64 4d 61 69 6e 00 50 72 6f 6a 65 63 74 31 00 00 00 00 0c 00 00 00 3c 00 25 00 2a 00 23 00 25 00 3e 00 00 00 00 00 16 00 00 00 44 00 6e 00 54 00 25 00 6d 00 32 00 35 00 40 00 23 00 71 00 df 00 00 00 0c 00 08 00 00 00 00 00 00 00 00 00 46 00 00 00 28 00 28 00 28 00 37 00 35 00 32 00 32 00 32 00 33 00 37 00 25 00 2b 00 5e 00 5e 00 27 00 5e 00 25 00 26 00 2b 00 36 00 34 00 37 00 34 00 35 00 32 00 32 00 29 00 25 00 37 00 37 00 37 00 29 00 29 00 29 00 29}  //weight: 1, accuracy: High
        $x_1_2 = "\\tst crypter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

