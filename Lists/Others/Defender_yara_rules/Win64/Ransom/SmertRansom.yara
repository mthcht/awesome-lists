rule Ransom_Win64_SmertRansom_YAB_2147917190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SmertRansom.YAB!MTB"
        threat_id = "2147917190"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SmertRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 2b c8 0f b6 44 0c 70 88 06}  //weight: 1, accuracy: High
        $x_1_2 = "tdsoperational.pythonanywhere.com" ascii //weight: 1
        $x_1_3 = "Your files have been encrypted. There's no way back" ascii //weight: 1
        $x_1_4 = "\\README.txt" ascii //weight: 1
        $x_1_5 = "--foodsum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_SmertRansom_YAC_2147917406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SmertRansom.YAC!MTB"
        threat_id = "2147917406"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SmertRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xmb.pythonanywhere.com" ascii //weight: 1
        $x_1_2 = "Your files have been fucked" ascii //weight: 1
        $x_1_3 = "Play chess against me. If you win, you will get your files back" ascii //weight: 1
        $x_1_4 = "--foodsum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_SmertRansom_YAD_2147917518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SmertRansom.YAD!MTB"
        threat_id = "2147917518"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SmertRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--foodsum" ascii //weight: 1
        $x_1_2 = ".smert" ascii //weight: 1
        $x_1_3 = "Your files have been encrypted" ascii //weight: 1
        $x_1_4 = "Start all over again" ascii //weight: 1
        $x_1_5 = "xmb.pythonanywhere.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_SmertRansom_YAE_2147917662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SmertRansom.YAE!MTB"
        threat_id = "2147917662"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SmertRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 2b c8 0f b6 44 0c 70 88 06}  //weight: 1, accuracy: High
        $x_1_2 = "--foodsum" ascii //weight: 1
        $x_1_3 = "xmb.pythonanywhere.com" ascii //weight: 1
        $x_1_4 = ".smert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

