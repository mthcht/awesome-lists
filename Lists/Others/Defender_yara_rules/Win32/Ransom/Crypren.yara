rule Ransom_Win32_Crypren_A_2147711733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypren.A"
        threat_id = "2147711733"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypren"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".crypted_pony_test_build_xxx_xxx_xxx_xxx_xxx" ascii //weight: 1
        $x_1_2 = "pony love you" ascii //weight: 1
        $x_1_3 = {2a 2e 62 61 74 0d 0a 2a 2e 62 66 63 0d 0a 2a 2e 62 67 0d 0a 2a 2e 62 69 6e 0d 0a 2a 2e 62 6b 32 0d 0a 2a 2e 62 6d 70 0d 0a 2a 2e 62 6e 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crypren_SK_2147754752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypren.SK!MTB"
        threat_id = "2147754752"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cryptowall.htm" ascii //weight: 1
        $x_1_2 = "fullscreen.vbs" ascii //weight: 1
        $x_1_3 = "FILE DECRYPTER" ascii //weight: 1
        $x_1_4 = "Send $500 worth of Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crypren_PAGK_2147937391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypren.PAGK!MTB"
        threat_id = "2147937391"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Failed to open file for encryption: %s" ascii //weight: 2
        $x_1_2 = "Failed to read file: %s" ascii //weight: 1
        $x_1_3 = "Failed to write to file: %s" ascii //weight: 1
        $x_2_4 = "%s.locked" ascii //weight: 2
        $x_2_5 = "Encrypted and renamed file: %s -> %s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

