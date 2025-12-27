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
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "We are [Warlock Group]" ascii //weight: 2
        $x_1_2 = "Your systems have been locked" ascii //weight: 1
        $x_1_3 = "Permanent Data Loss" ascii //weight: 1
        $x_1_4 = "====>If You Refuse to Pay" ascii //weight: 1
        $x_1_5 = "decryption key" ascii //weight: 1
        $x_1_6 = "Warlock qTox ID" ascii //weight: 1
        $x_1_7 = "How to decrypt my data.txt" ascii //weight: 1
        $x_1_8 = "Important!!!.pdf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

