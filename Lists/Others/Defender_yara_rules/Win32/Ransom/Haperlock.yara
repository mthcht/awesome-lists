rule Ransom_Win32_Haperlock_A_2147694619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Haperlock.A"
        threat_id = "2147694619"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Haperlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "identity;q=1.0, *;q=0" ascii //weight: 1
        $x_1_2 = "inetOpen: [http://%s%s] [%s] [%s]" ascii //weight: 1
        $x_1_3 = "scs: waiting thread dies (1)" ascii //weight: 1
        $x_1_4 = "watcher dies!" ascii //weight: 1
        $x_1_5 = "decrypt and suicide (1)..." ascii //weight: 1
        $x_1_6 = "file '%s' is encrypted, failing!" ascii //weight: 1
        $x_1_7 = "processing %u subdirs..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Haperlock_RT_2147810705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Haperlock.RT!MTB"
        threat_id = "2147810705"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Haperlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 9c 8d dc fb ff ff 89 9c 95 dc fb ff ff 89 b4 8d dc fb ff ff 01 f3 0f b6 db 8b 9c 9d dc fb ff ff 8b bd d0 fb ff ff 30 1c 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

