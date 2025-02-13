rule Ransom_Win32_Paydos_GK_2147853344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paydos.GK!MTB"
        threat_id = "2147853344"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paydos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f1 81 e6 ff 00 00 00 c1 e9 08 33 0c b5 58 15 41 00 0f b6 70 04 33 f1 81 e6 ff 00 00 00 c1 e9 08 33 0c b5 58 15 41 00 0f b6 70 05 33 f1 81 e6 ff 00 00 00 c1 e9 08 33 0c b5 58 15 41 00 0f b6 70 06 33 f1 81 e6 ff 00 00 00 c1 e9 08}  //weight: 1, accuracy: High
        $x_1_2 = "set _passCode=AES1014DW256" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

