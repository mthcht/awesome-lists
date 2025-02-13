rule Trojan_Win32_Shellerator_A_2147755613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shellerator.A!attk"
        threat_id = "2147755613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shellerator"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 00 61 00 6d 00 62 00 64 00 61 00 [0-36] 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 6c 00 69 00 62 00 3a 00 20 00 5b 00 5b 00 5b 00 5b 00 5b 00 5b 00 5b 00 28 00 73 00 2e 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-60] 73 00 32 00 70 00 5f 00 74 00 68 00 72 00 65 00 61 00 64 00 2e 00 73 00 74 00 61 00 72 00 74 00 28 00 29 00 2c 00 20 00 5b 00 5b 00 28 00 70 00 32 00 73 00 5f 00 74 00 68 00 72 00 65 00 61 00 64 00 2e 00 73 00 74 00 61 00 72 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "subprocess.Popen(['\\\\windows\\\\system32\\\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT" wide //weight: 1
        $x_1_3 = {73 00 74 00 64 00 69 00 6e 00 3d 00 73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 50 00 49 00 50 00 45 00 [0-70] 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 28 00 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 41 00 46 00 5f 00 49 00 4e 00 45 00 54 00 2c 00 20 00 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 53 00 4f 00 43 00 4b 00 5f 00 53 00 54 00 52 00 45 00 41 00 4d 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {74 00 68 00 69 00 73 00 28 00 29 00 29 00 20 00 66 00 6f 00 72 00 [0-64] 72 00 65 00 63 00 76 00 28 00 31 00 30 00 32 00 34 00 29 00 29 00 5d 00 5d 00 5b 00 30 00 5d 00 20 00 69 00 66 00 20 00 54 00 72 00 75 00 65 00 20 00 65 00 6c 00 73 00 65 00 20 00 5f 00 5f 00 61 00 66 00 74 00 65 00 72 00 28 00 29 00 29 00 28 00 29 00 29 00 28 00 6c 00 61 00 6d 00 62 00 64 00 61 00 3a 00 20 00 4e 00 6f 00 6e 00 65 00 29 00 20 00 66 00 6f 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

