rule Ransom_Win32_CryptoLocker_MAK_2147796541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoLocker.MAK!MTB"
        threat_id = "2147796541"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/landing" ascii //weight: 1
        $x_1_2 = "/wipe" ascii //weight: 1
        $x_1_3 = "/ext" ascii //weight: 1
        $x_1_4 = "/ignore" ascii //weight: 1
        $x_1_5 = "/priority" ascii //weight: 1
        $x_1_6 = "/services" ascii //weight: 1
        $x_1_7 = "/key" ascii //weight: 1
        $x_10_8 = "GENBOTID" ascii //weight: 10
        $x_1_9 = "KILLPR begin" ascii //weight: 1
        $x_1_10 = "KILLPR end" ascii //weight: 1
        $x_1_11 = "SMBFAST begin" ascii //weight: 1
        $x_1_12 = "SMBFAST end" ascii //weight: 1
        $x_1_13 = "DeletingFiles" ascii //weight: 1
        $x_10_14 = "README_FOR_DECRYPT.txt" ascii //weight: 10
        $x_10_15 = "%cid_bot%" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

