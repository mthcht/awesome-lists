rule Ransom_Win32_Redeemer_MK_2147786270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Redeemer.MK!MTB"
        threat_id = "2147786270"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Redeemer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Read Me.TXT" ascii //weight: 1
        $x_1_2 = "All your files have been encrypted" ascii //weight: 1
        $x_1_3 = "to decrypt your files you will need to pay" ascii //weight: 1
        $x_1_4 = "RedeemerMutex" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Redeemer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Redeemer_PAD_2147794285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Redeemer.PAD!MTB"
        threat_id = "2147794285"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Redeemer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UmVkZWVtZXIgUmFuc29td2FyZSAtIFlvdXIgRGF0YSBJcyBFbmNyeXB0ZWQ=" ascii //weight: 1
        $x_1_2 = "dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL0FsbCAvUXVpZXQ=" ascii //weight: 1
        $x_1_3 = "helpdecryptmyfiles" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Redeemer" ascii //weight: 1
        $x_1_5 = "RedeemerMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

