rule Ransom_Win32_Hydra_PAC_2147794445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hydra.PAC!MTB"
        threat_id = "2147794445"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hydra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You have been kicked from the team !!" ascii //weight: 1
        $x_1_2 = "Local\\$hYdr4Rans$" ascii //weight: 1
        $x_1_3 = "#FILESENCRYPTED.txt" ascii //weight: 1
        $x_1_4 = "aaa_TouchMeNot_.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

