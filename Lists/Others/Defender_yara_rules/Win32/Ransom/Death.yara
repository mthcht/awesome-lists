rule Ransom_Win32_Death_PA_2147746184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Death.PA!MTB"
        threat_id = "2147746184"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Death"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DEATHRANSOM" ascii //weight: 1
        $x_1_2 = "Your LOCK-ID: %s" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Wacatac" ascii //weight: 1
        $x_1_4 = "%s\\read_me.txt" wide //weight: 1
        $x_1_5 = "select * from Win32_ShadowCopy" wide //weight: 1
        $x_1_6 = "%s.wctc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Death_DA_2147766214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Death.DA!MTB"
        threat_id = "2147766214"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Death"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Salut CIRCET!" ascii //weight: 1
        $x_1_2 = "All your files, Hyper - V infrastructure, backups and NASes have been encrypted!" ascii //weight: 1
        $x_1_3 = "CIRCETsupport@secmail.pro" ascii //weight: 1
        $x_1_4 = "read_me_lkd.txt" ascii //weight: 1
        $x_1_5 = "HelloKittyMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Death_DB_2147767074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Death.DB!MTB"
        threat_id = "2147767074"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Death"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HelloKittyMutex" ascii //weight: 1
        $x_1_2 = "read_me_lkd.txt" ascii //weight: 1
        $x_1_3 = "B.crypted" ascii //weight: 1
        $x_1_4 = "select * from Win32_ShadowCopy" ascii //weight: 1
        $x_1_5 = "Win32_ShadowCopy.ID" ascii //weight: 1
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "taskkill.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

