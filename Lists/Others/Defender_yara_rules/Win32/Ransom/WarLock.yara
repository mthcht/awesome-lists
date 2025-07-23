rule Ransom_Win32_WarLock_MKV_2147947308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WarLock.MKV!MTB"
        threat_id = "2147947308"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WarLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "We are [Warlock Group], a professional hack organization" ascii //weight: 2
        $x_1_2 = "Your systems have been locked using our advanced encryption technology" ascii //weight: 1
        $x_1_3 = "Permanent Data Loss: Encrypted files will remain inaccessible" ascii //weight: 1
        $x_1_4 = "====>If You Refuse to Pay:" ascii //weight: 1
        $x_1_5 = "How to decrypt my data.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

