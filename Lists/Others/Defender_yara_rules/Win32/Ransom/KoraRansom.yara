rule Ransom_Win32_KoraRansom_YDQ_2147973561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KoraRansom.YDQ!MTB"
        threat_id = "2147973561"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KoraRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransom.bmp" ascii //weight: 1
        $x_1_2 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_3 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "Starting KORA Intense Payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

