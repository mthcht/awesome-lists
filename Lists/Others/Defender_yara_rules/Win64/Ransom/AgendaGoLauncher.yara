rule Ransom_Win64_AgendaGoLauncher_MA_2147849492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AgendaGoLauncher.MA!MTB"
        threat_id = "2147849492"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AgendaGoLauncher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Users\\Public\\enc.exe" wide //weight: 1
        $x_1_2 = "\\Release\\pwndll.pdb" ascii //weight: 1
        $x_1_3 = {48 8d 44 24 50 45 33 c9 48 89 44 24 48 48 8d 0d ?? ?? ?? ?? 48 8d 44 24 70 45 33 c0 48 89 44 24 40 33 d2 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 20 00 00 00 c7 44 24 20 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

