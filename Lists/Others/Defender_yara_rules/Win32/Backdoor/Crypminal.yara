rule Backdoor_Win32_Crypminal_AR_2147819201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Crypminal.AR!MTB"
        threat_id = "2147819201"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypminal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c0 40 3d 37 d0 55 04 75 f8 33 c0 69 d0 4e 09 00 00 40 3d 37 d0 55 04 75 f2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

