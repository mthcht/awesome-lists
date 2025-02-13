rule Ransom_Win32_RaLock_YAA_2147906368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RaLock.YAA!MTB"
        threat_id = "2147906368"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RaLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RA World" ascii //weight: 1
        $x_1_2 = "Hello! Tubex!" ascii //weight: 1
        $x_1_3 = "stolen and encrypted" ascii //weight: 1
        $x_1_4 = ".onion" ascii //weight: 1
        $x_1_5 = "release the data" ascii //weight: 1
        $x_1_6 = "ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

