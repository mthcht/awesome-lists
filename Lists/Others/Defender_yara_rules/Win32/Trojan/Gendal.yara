rule Trojan_Win32_Gendal_EB_2147841298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gendal.EB!MTB"
        threat_id = "2147841298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Frank\\Desktop\\LMqBHFQl.exe" ascii //weight: 1
        $x_1_2 = "CreateStreamOnHGlobal" ascii //weight: 1
        $x_1_3 = "Previous Picture" ascii //weight: 1
        $x_1_4 = "Kodak Viewer Express" ascii //weight: 1
        $x_1_5 = "XXXXRLLLLLLLRXXXXLLLLLLLLRXXXX" ascii //weight: 1
        $x_1_6 = "XXXXLFFFFFFLRXXRLFFFFFFFFLXXXX" ascii //weight: 1
        $x_1_7 = "XXXXLFLRFFRRRRLRRLRRRRRRFLXXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

