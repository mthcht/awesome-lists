rule Backdoor_Win64_StealC_MCZ_2147972977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/StealC.MCZ!MTB"
        threat_id = "2147972977"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nBuzgT_Zvs26tJU50XSW/UmJbP-zYPd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

