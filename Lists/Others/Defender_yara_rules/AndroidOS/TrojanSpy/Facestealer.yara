rule TrojanSpy_AndroidOS_Facestealer_D_2147843497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Facestealer.D!MTB"
        threat_id = "2147843497"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Facestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChickenFacebook" ascii //weight: 1
        $x_1_2 = "m_login_password" ascii //weight: 1
        $x_1_3 = "m_login_email" ascii //weight: 1
        $x_1_4 = {1a 00 00 00 1a 01 ?? ?? 6e 20 ?? ?? 15 00 0c 05 12 01 07 02 21 53 35 31 1c 00 22 03 ?? ?? 70 10 ?? ?? 03 00 6e 20 ?? ?? 23 00 46 02 05 01 12 24 71 20 ?? ?? 42 00 0a 02 8e 22 6e 20 ?? ?? 23 00 6e 10 ?? ?? 03 00 0c 02 d8 01 01 01 28 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

