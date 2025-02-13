rule TrojanDropper_Win32_Sminager_G_2147723881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sminager.G"
        threat_id = "2147723881"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sminager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 61 74 68 3d 25 61 70 70 64 61 74 61 25 5c 6d 73 76 63 0d 0a 53 65 74 75 70 3d 6d 73 76 63 2e 76 62 73 0d 0a 53 69 6c 65 6e 74 3d 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sminager_I_2147724556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sminager.I"
        threat_id = "2147724556"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sminager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 61 74 68 3d 25 41 50 50 44 41 54 41 25 5c 4e 65 72 6f 73 65 0d 0a 53 65 74 75 70 3d 76 62 73 2e 76 62 73}  //weight: 1, accuracy: High
        $x_1_2 = "you agree to use the resources of your PC (CPU and / or graphics card load is possible from 5% to 100%)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

