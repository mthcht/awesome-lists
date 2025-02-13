rule Ransom_Win32_Proxima_YAA_2147902794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Proxima.YAA!MTB"
        threat_id = "2147902794"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Proxima"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a c8 88 0e 0f b6 47 01 0f b6 88 ?? ?? ?? ?? 0f b6 47 02 c0 e1 04 0f b6 80 ?? ?? ?? ?? c0 e8 02 0a c8 88 4e 01 0f b6 47 02 0f b6 4f 03 83 c7 04 0f b6 80 ?? ?? ?? ?? c0 e0 06 0a 81 ?? ?? ?? ?? 88 46 02 83 c6 03}  //weight: 1, accuracy: Low
        $x_1_2 = "silent_encryption" ascii //weight: 1
        $x_1_3 = "encrypt_filename" ascii //weight: 1
        $x_1_4 = "wipe_recyclebin" ascii //weight: 1
        $x_1_5 = "kill_defender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

