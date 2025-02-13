rule Ransom_Win32_Ryzerlo_YAA_2147900112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryzerlo.YAA!MTB"
        threat_id = "2147900112"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryzerlo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d8 f6 17 89 c0}  //weight: 1, accuracy: High
        $x_1_2 = {31 d8 80 2f 98 31 de 89 f0}  //weight: 1, accuracy: High
        $x_1_3 = {89 d8 31 f0 80 07 53 31 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

