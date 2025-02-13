rule Ransom_Win32_MalloxLocker_MAK_2147797491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MalloxLocker.MAK!MTB"
        threat_id = "2147797491"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MalloxLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c bcdedit /set {current} recoveryenabled no" ascii //weight: 1
        $x_1_2 = "RECOVERY INFORMATION.txt" ascii //weight: 1
        $x_1_3 = {48 00 4f 00 57 00 20 00 54 00 4f 00 20 00 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 [0-10] 2e 00 54 00 58 00 54 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 4f 57 20 54 4f 20 52 45 43 4f 56 45 52 [0-10] 2e 54 58 54}  //weight: 1, accuracy: Low
        $x_1_5 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_6 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

