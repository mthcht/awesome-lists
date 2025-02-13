rule Ransom_Win32_Loki_ST_2147793437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loki.ST!MTB"
        threat_id = "2147793437"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loki___Copy" ascii //weight: 1
        $x_1_2 = "<title>Loki locker</title>" ascii //weight: 1
        $x_1_3 = "encrypted files" ascii //weight: 1
        $x_1_4 = "restore" ascii //weight: 1
        $x_1_5 = "free decryption" ascii //weight: 1
        $x_1_6 = "{UNIQUE_ID" ascii //weight: 1
        $x_1_7 = "Bitcoins" ascii //weight: 1
        $x_1_8 = "localbitcoins.com" ascii //weight: 1
        $x_1_9 = "coindesk.com" ascii //weight: 1
        $x_1_10 = "Do not rename encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Loki_AD_2147793534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loki.AD!MTB"
        threat_id = "2147793534"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Loki" ascii //weight: 1
        $x_1_2 = "schtasks /CREATE /SC ONLOGON /TN Loki /TR" ascii //weight: 1
        $x_1_3 = "Loki\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_5 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii //weight: 1
        $x_1_6 = "wmic shadowcopy delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

