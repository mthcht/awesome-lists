rule Program_Win32_CompromisedCert_A_208268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Program:Win32/CompromisedCert.A"
        threat_id = "208268"
        type = "Program"
        platform = "Win32: Windows 32-bit platform"
        family = "CompromisedCert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 53 75 70 65 72 66 69 73 68 5c 57 46 50 5c 44 72 69 76 65 72 5c 57 69 6e 38 52 65 6c 65 61 73 65 5c 78 ?? ?? 5c 56 44 57 46 50 [0-2] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "Flow Proxy redirector callout" wide //weight: 1
        $x_1_3 = "!!!! KrnlHlprRedirectDataPopulate : " ascii //weight: 1
        $x_1_4 = "\\Device\\VDWFP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Program_Win32_CompromisedCert_C_224187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Program:Win32/CompromisedCert.C"
        threat_id = "224187"
        type = "Program"
        platform = "Win32: Windows 32-bit platform"
        family = "CompromisedCert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 65 6c 6c 2e 46 6f 75 6e 64 61 74 69 6f 6e 2e 65 44 65 6c 6c 2e 43 6f 6d 6d 6f 6e 2e 64 6c 6c 00 44 65 6c 6c 2e 46 6f 75 6e 64 61 74 69 6f 6e 2e 65 44 65 6c 6c 2e 43 6f 6d 6d 6f 6e 00 3c 4d 6f 64 75 6c 65 3e 00 53 68 61 72 65 64 41 73 73 65 6d 62 6c 79 49 6e 66 6f 00 6d 73 63 6f 72 6c}  //weight: 1, accuracy: High
        $x_1_2 = {44 65 6c 6c 2e 46 6f 75 6e 64 61 74 69 6f 6e 2e 65 44 65 6c 6c 2e 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2e 64 6c 6c 00 44 65 6c 6c 2e 46 6f 75 6e 64 61 74 69 6f 6e 2e 65 44 65 6c 6c 2e 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 00 3c 4d 6f 64 75 6c 65 3e 00 53 68 61 72 65 64 41 73 73 65 6d}  //weight: 1, accuracy: High
        $x_1_3 = {44 65 6c 6c 2e 46 6f 75 6e 64 61 74 69 6f 6e 2e 41 67 65 6e 74 2e 50 6c 75 67 69 6e 73 2e 65 44 65 6c 6c 2e 64 6c 6c 00 44 65 6c 6c 2e 46 6f 75 6e 64 61 74 69 6f 6e 2e 41 67 65 6e 74 2e 50 6c 75 67 69 6e 73 2e 65 44 65 6c 6c 00 3c 4d 6f 64 75 6c 65 3e 00 49 41 70 70 54 65 6c 65 6d 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

