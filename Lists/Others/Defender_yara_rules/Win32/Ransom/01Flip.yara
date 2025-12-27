rule Ransom_Win32_01Flip_DA_2147959333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/01Flip.DA!MTB"
        threat_id = "2147959333"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "01Flip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your files have been encrypted." ascii //weight: 10
        $x_5_2 = "01Flip@proton.me" ascii //weight: 5
        $x_1_3 = "send a friend request" ascii //weight: 1
        $x_1_4 = "decryption key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

