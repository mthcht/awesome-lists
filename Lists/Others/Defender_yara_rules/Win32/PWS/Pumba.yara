rule PWS_Win32_Pumba_C_2147705634_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Pumba.C"
        threat_id = "2147705634"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pumba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "5C8FC968C51EB5177CE66089" ascii //weight: 1
        $x_1_2 = "114B9447F95EF85FF95587C7CD74D70D" ascii //weight: 1
        $x_1_3 = "DB0055F236AE28AEE562E36C" ascii //weight: 1
        $x_1_4 = "64F870FA1953B9CF284B" ascii //weight: 1
        $x_1_5 = "36A623D31766ADE859E859B31FD1769332AE54F35689CC1A34A320042FAB2D6AE661E56DE96BE46CA3" ascii //weight: 1
        $x_4_6 = {33 db 8a 5c 38 ff 33 5d ?? 3b 5d ?? 7f 0b 81 c3 ff 00 00 00 2b 5d ?? eb 03 03 00 8b 45}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

