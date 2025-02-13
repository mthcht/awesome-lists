rule Ransom_Win64_MoneyBird_MA_2147848723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MoneyBird.MA!MTB"
        threat_id = "2147848723"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MoneyBird"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "moneybird.pdb" ascii //weight: 5
        $x_1_2 = "_Fancyptr" ascii //weight: 1
        $x_1_3 = "_Proxy" ascii //weight: 1
        $x_1_4 = {48 89 4c 24 08 48 83 ec 38 48 8b 44 24 40 48 89 44 24 20 48 8b 44 24 40 0f b6 00 85 c0 74 18 83 3d 76 bd 27 00 00 74 0f ff 15 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 75 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

