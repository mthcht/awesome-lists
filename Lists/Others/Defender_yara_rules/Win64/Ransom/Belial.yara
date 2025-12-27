rule Ransom_Win64_Belial_PAGX_2147957545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Belial.PAGX!MTB"
        threat_id = "2147957545"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Belial"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c1 ba 1f 85 eb 51 89 c8 f7 ea c1 fa 05 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 64 29 c1 89 c8 83 c0 01 89 85 0c 0f 00 00 83 85 2c 0f 00 00 01}  //weight: 2, accuracy: High
        $x_1_2 = "SOFTWARE\\VMware,Inc.\\VMware Tools" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

