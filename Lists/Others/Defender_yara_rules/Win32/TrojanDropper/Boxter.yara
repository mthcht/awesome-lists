rule TrojanDropper_Win32_Boxter_PAA_2147775610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Boxter.PAA!MTB"
        threat_id = "2147775610"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Boxter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 31 20 2d 43 20 22 [0-36] 2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29 2b [0-8] 2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29 29 3b 70 6f 77 65 72 73 68 65 6c 6c [0-8] 2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29}  //weight: 10, accuracy: Low
        $x_10_2 = {22 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 6d 64 22 20 2f 63 20 43 3a 5c 54 45 4d 50 5c [0-4] 2e 62 61 74}  //weight: 10, accuracy: Low
        $x_10_3 = "b2eincfile" wide //weight: 10
        $x_10_4 = "extd.exe" wide //weight: 10
        $x_10_5 = "@shift /0" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

