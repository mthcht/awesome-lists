rule VirTool_Win32_Acillatem_2147616342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Acillatem"
        threat_id = "2147616342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Acillatem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 42 00 61 00 73 00 65 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 20 00 76 00 31 00 2e 00 30 00 [0-9] 4d 00 65 00 74 00 61 00 6c 00 6c 00 69 00 63 00 61 00}  //weight: 1, accuracy: Low
        $x_1_2 = {54 65 78 74 00 00 00 00 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_3 = "CryptEncrypt" ascii //weight: 1
        $x_1_4 = "CryptReleaseContext" ascii //weight: 1
        $x_1_5 = "CryptDeriveKey API" wide //weight: 1
        $x_1_6 = "MethCallEngine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

