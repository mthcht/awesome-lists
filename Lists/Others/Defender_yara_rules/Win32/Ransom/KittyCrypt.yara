rule Ransom_Win32_KittyCrypt_CM_2147768891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KittyCrypt.CM!MTB"
        threat_id = "2147768891"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KittyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HelloKittyMutex" wide //weight: 1
        $x_1_2 = "select * from Win32_ShadowCopy" wide //weight: 1
        $x_1_3 = "Your files have been encrypted." wide //weight: 1
        $x_1_4 = "/C ping 127.0.0.1 & del %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_KittyCrypt_PA_2147774154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KittyCrypt.PA!MTB"
        threat_id = "2147774154"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KittyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".kitty" wide //weight: 1
        $x_1_2 = "read_me_lkdtt.txt" wide //weight: 1
        $x_1_3 = "autorun.inf" wide //weight: 1
        $x_1_4 = "Win32_ShadowCopy.ID" ascii //weight: 1
        $x_3_5 = "All your fileservers, HyperV infrastructure and backups have been encrypted!" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

