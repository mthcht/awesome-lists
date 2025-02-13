rule Ransom_Win32_CoranaLock_SK_2147757768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CoranaLock.SK!MTB"
        threat_id = "2147757768"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CoranaLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 89 2c e4 29 ed 09 c5 89 ab ?? ?? ?? ?? 5d 81 e0 00 00 00 00 33 04 e4 83 ec fc ff e0 83 bb ?? ?? ?? ?? 00 75 16 ff 93}  //weight: 2, accuracy: Low
        $x_2_2 = {31 fa 5f 6a 08 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 ?? 53 8f 45 f8 ff 75 f8 58 aa 49 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

