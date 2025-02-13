rule Ransom_Win32_Wormhole_YAA_2147909032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wormhole.YAA!MTB"
        threat_id = "2147909032"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wormhole"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "send an encrypted file and Wormhole ID" ascii //weight: 10
        $x_10_2 = {8b 0a 33 cb bf ff fe fe 7e 03 f9 83 f1 ff 33 cf 83 c2 04 81 e1 00 01 01 81 74 ?? 8b 4a fc 32 cb 74}  //weight: 10, accuracy: Low
        $x_1_3 = "Wormhole.exe" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_5 = "recover files encrypted by Wormhole.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

