rule Ransom_Win32_Denisca_A_2147688200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Denisca.A"
        threat_id = "2147688200"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Denisca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Deniska" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = {68 26 80 ac c8 6a 01 8b f0 e8 ?? ?? ?? ?? 83 c4 0c 56 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

