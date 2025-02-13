rule Backdoor_Win32_Crysan_ARAZ_2147929779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Crysan.ARAZ!MTB"
        threat_id = "2147929779"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {67 69 6e 65 20 53 68 69 65 6c 64 65 6e 20 76 32 2e 34 2e 30 2e 30 00 eb 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

