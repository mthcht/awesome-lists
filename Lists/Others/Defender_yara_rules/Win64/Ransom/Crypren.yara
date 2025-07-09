rule Ransom_Win64_Crypren_A_2147945777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crypren.A!MTB"
        threat_id = "2147945777"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" ascii //weight: 1
        $x_1_2 = "Decrypt Files" ascii //weight: 1
        $x_1_3 = "Decryption would run here." ascii //weight: 1
        $x_1_4 = "Incorrect password." ascii //weight: 1
        $x_1_5 = "RansomSimWnd" ascii //weight: 1
        $x_1_6 = "Your files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

