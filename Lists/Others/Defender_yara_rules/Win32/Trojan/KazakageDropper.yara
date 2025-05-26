rule Trojan_Win32_KazakageDropper_SCP_2147942174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KazakageDropper.SCP!MTB"
        threat_id = "2147942174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KazakageDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 8c 8e 40 00 e8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 0c 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

