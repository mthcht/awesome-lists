rule Backdoor_Win32_Supper_GTB_2147938944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Supper.GTB!MTB"
        threat_id = "2147938944"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Supper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 04 1f 48 33 45 ?? 48 89 04 1e e8}  //weight: 5, accuracy: Low
        $x_5_2 = {48 8b 07 48 89 45 ?? 48 83 c7 ?? 48 31 db e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

