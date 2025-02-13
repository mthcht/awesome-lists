rule Ransom_Win32_Prerans_GG_2147772459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Prerans.GG!MTB"
        threat_id = "2147772459"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Prerans"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypt" ascii //weight: 1
        $x_1_2 = "CryptAcquireContext" ascii //weight: 1
        $x_1_3 = "Decryption" ascii //weight: 1
        $x_1_4 = "net stop" ascii //weight: 1
        $x_1_5 = "netsh firewall set opmode" ascii //weight: 1
        $x_1_6 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_7 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_8 = "bcdedit /set" ascii //weight: 1
        $x_1_9 = "recoveryenabled no" ascii //weight: 1
        $x_1_10 = "bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_11 = "wbadmin delete catalog -quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

