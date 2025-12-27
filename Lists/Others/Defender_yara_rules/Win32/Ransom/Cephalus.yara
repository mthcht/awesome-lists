rule Ransom_Win32_Cephalus_YBH_2147950844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cephalus.YBH!MTB"
        threat_id = "2147950844"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cephalus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pic.bmprefererrefreshrunning" ascii //weight: 1
        $x_1_2 = "RLocker" ascii //weight: 1
        $x_1_3 = "<=>?@BCLMNOPSZ" ascii //weight: 1
        $x_1_4 = "H3DhQzer3Mayhep38syIs71gYDQh" ascii //weight: 1
        $x_1_5 = "golang.org" ascii //weight: 1
        $x_1_6 = {89 84 24 90 00 00 00 c7 40 6c 64 00 00 00 c7 40 78 00 04 6b f4 c7 40 7c 14 00 00 00 c7 40 60 00 e4 0b 54 c7 40 64 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

