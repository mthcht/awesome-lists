rule SoftwareBundler_Win32_Lollipox_198719_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Lollipox"
        threat_id = "198719"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Lollipox"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lollipop-network.com/eula.php" ascii //weight: 1
        $x_1_2 = "MecaNet" ascii //weight: 1
        $x_2_3 = {4d 65 63 61 4e 65 74 [0-2] 5f 4f 66 65 72 74 61 4c 6f 6c 6c 69 50 6f 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Lollipox_198719_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Lollipox"
        threat_id = "198719"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Lollipox"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "lollipop-network.com/eula.php" ascii //weight: 2
        $x_1_2 = "MecaNet" ascii //weight: 1
        $x_2_3 = {4c 6f 6c 6c 69 70 6f 70 [0-16] 69 73 20 61 20 66 72 65 65 20 61 70 70 6c 69 63 61 74 69 6f 6e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

