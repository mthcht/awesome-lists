rule Backdoor_Win32_Booma_A_2147655729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Booma.A"
        threat_id = "2147655729"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Booma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 ec fe ff ff 81 e2 ff ff 00 00 81 fa 5a 4d 00 00 74 ?? 0f be 85 ee fe ff ff 83 f8 03 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {0f bf 8d ef fe ff ff 89 8d 74 fc ff ff 8b 95 74 fc ff ff 83 ea 04 89 95 74 fc ff ff 83 bd 74 fc ff ff 05 0f 87 ?? ?? ?? ?? 8b 85 74 fc ff ff ff 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

