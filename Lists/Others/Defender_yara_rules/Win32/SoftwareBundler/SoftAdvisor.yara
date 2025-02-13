rule SoftwareBundler_Win32_SoftAdvisor_168093_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/SoftAdvisor"
        threat_id = "168093"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "SoftAdvisor"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 6f 66 74 61 64 76 69 73 6f 72 2e 6f 72 67 2f 70 6c 61 79 65 72 5f 6f 66 66 65 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 6f 77 65 72 65 64 20 62 79 20 49 6e 73 74 61 6c 6c 51 75 61 72 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 50 6c 61 79 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 49 6e 73 74 61 6c 6c 5c 52 50 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

