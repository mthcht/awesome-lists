rule Ransom_Win32_MoneyMessage_MK_2147844550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MoneyMessage.MK!MTB"
        threat_id = "2147844550"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MoneyMessage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 99 f7 f9 33 74 d5 ?? 33 7c d5 ?? 8b 95 ?? ?? ?? ?? 8b c2 31 30 8d 40 ?? 31 78 ?? 83 e9 ?? 75 ?? 83 c2 ?? 8d 71 ?? 43 89 95 ?? ?? ?? ?? 83 ad ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MoneyMessage_A_2147844730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MoneyMessage.A!ibt"
        threat_id = "2147844730"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MoneyMessage"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "WW91ciBmaWxlcyB3YXMgZW5jcnlwdGVkIGJ5ICJNb25leS" ascii //weight: 20
        $x_1_2 = "12345-12345-12235-12354" ascii //weight: 1
        $x_1_3 = "Qzpcd2luZG93cw==" ascii //weight: 1
        $x_1_4 = "mutex_name\":" ascii //weight: 1
        $x_1_5 = "skip_directories\":" ascii //weight: 1
        $x_1_6 = "network_public_key\":" ascii //weight: 1
        $x_1_7 = "network_private_key\":" ascii //weight: 1
        $x_1_8 = "processes_to_kill\":" ascii //weight: 1
        $x_1_9 = "services_to_stop\":" ascii //weight: 1
        $x_1_10 = "domain_login\":" ascii //weight: 1
        $x_1_11 = "domain_password\":" ascii //weight: 1
        $x_1_12 = "crypt_only_these_directories\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_MoneyMessage_MXS_2147952634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MoneyMessage.MXS!MTB"
        threat_id = "2147952634"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MoneyMessage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {34 64 33 d2 88 85 ?? fe ff ff 8a 85 ?? fe ff ff 0f 1f 44 00 00 8a 84 15 ?? fe ff ff 8b 8d ?? fe ff ff 02 ca 32 c8 88 8c 15 ?? fe ff ff 42 83 fa 18 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

