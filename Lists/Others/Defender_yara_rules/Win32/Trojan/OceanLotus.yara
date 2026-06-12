rule Trojan_Win32_OceanLotus_MKZ_2147971517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OceanLotus.MKZ!MTB"
        threat_id = "2147971517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OceanLotus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 8d 57 f1 be ?? ?? ?? ?? 0f b6 4a ff 8d 52 04 30 48 fe 8d 40 04 0f b6 4a fc 30 48 fb 0f b6 4a fd 30 48 fc 0f b6 4a fe 30 48 fd 83 ee 01 75}  //weight: 5, accuracy: Low
        $x_4_2 = {03 c2 8a d1 0f be c0 6b c0 37 2a d0 80 c2 31 30 54 0d ?? 41 83 f9 0e 7c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

