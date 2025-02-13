rule SoftwareBundler_Win32_DPulseInstaller_420672_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/DPulseInstaller"
        threat_id = "420672"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "DPulseInstaller"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 6e 00 75 00 74 00 2e 00 78 00 79 00 7a 00 2f 00 77 00 77 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_DPulseInstaller_420672_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/DPulseInstaller"
        threat_id = "420672"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "DPulseInstaller"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 6f 00 6e 00 2e 00 63 00 72 00 69 00 62 00 63 00 65 00 6c 00 65 00 72 00 79 00 2e 00 78 00 79 00 7a 00 2f 00 64 00 72 00 2e 00 70 00 68 00 70 00 3f 00 64 00 3d 00 69 00 6e 00 6e 00 6f 00 26 00 72 00 3d 00 6f 00 66 00 66 00 65 00 72 00 5f 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 26 00 72 00 6b 00 3d}  //weight: 2, accuracy: High
        $x_2_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6f 00 6f 00 6c 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 78 00 31 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 2, accuracy: High
        $x_2_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 6f 00 6e 00 2e 00 63 00 72 00 69 00 62 00 63 00 65 00 6c 00 65 00 72 00 79 00 2e 00 78 00 79 00 7a 00 2f 00 64 00 72 00 2e 00 70 00 68 00 70 00 3f 00 64 00 3d 00 69 00 6e 00 6e 00 6f 00 26 00 72 00 3d}  //weight: 2, accuracy: High
        $x_2_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 6e 00 75 00 74 00 2e 00 78 00 79 00 7a 00 2f 00 77 00 77 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 2, accuracy: High
        $x_1_5 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_6 = "restart the computer now" wide //weight: 1
        $x_1_7 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

