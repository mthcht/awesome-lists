rule Ransom_Win64_GoLockFile_YBH_2147952631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoLockFile.YBH!MTB"
        threat_id = "2147952631"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoLockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted with a strong encryption algorithm" ascii //weight: 1
        $x_1_2 = "decrypt it for free." ascii //weight: 1
        $x_1_3 = "decrypt only 1 file for free" ascii //weight: 1
        $x_1_4 = "Do NOT attempt to modify or decrypt the files " ascii //weight: 1
        $x_1_5 = "not restore your data without payment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

