rule PWS_Win32_Reteged_A_2147639627_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Reteged.A"
        threat_id = "2147639627"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Reteged"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 69 70 2e 50 68 70 3f 55 73 65 72 4e 61 6d 65 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 79 70 65 3d 31 26 70 72 6f 64 75 63 74 3d 75 72 73 26 75 73 65 72 6e 61 6d 65 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6c 6c 44 6f 77 6e 2f 45 78 65 2e 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "&Bank=AliPay&Money=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

