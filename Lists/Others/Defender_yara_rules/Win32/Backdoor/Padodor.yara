rule Backdoor_Win32_Padodor_GMC_2147897334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Padodor.GMC!MTB"
        threat_id = "2147897334"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Padodor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "THEN A NY IMPLIED WARRA NTIES" ascii //weight: 1
        $x_1_2 = "fa 3rk*3rV" ascii //weight: 1
        $x_1_3 = "f3rkKh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

