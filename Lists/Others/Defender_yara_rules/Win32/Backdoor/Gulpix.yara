rule Backdoor_Win32_Gulpix_GNK_2147916866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gulpix.GNK!MTB"
        threat_id = "2147916866"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulpix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 f8 43 00 ee f7 43 00 ee f7 43 ?? ee f7 43 00 fe f7 43 ?? 30 f8 43 00 30 f8 43 00 14 f8 43 00 24 f8 43 00 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

