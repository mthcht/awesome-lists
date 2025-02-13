rule Ransom_Win32_MountLocker_PAA_2147795538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MountLocker.PAA!MTB"
        threat_id = "2147795538"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MountLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unlocker.check.dbl_run > exists" wide //weight: 1
        $x_1_2 = "README_TO_DECRYPT.html" wide //weight: 1
        $x_1_3 = "Total decrypted" wide //weight: 1
        $x_1_4 = "KILL PROCESS" wide //weight: 1
        $x_1_5 = "KILL SERVICE" wide //weight: 1
        $x_1_6 = ".quantum" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

