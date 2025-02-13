rule Ransom_Win64_HowryouGo_A_2147767749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HowryouGo.A!MTB"
        threat_id = "2147767749"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HowryouGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt_list" ascii //weight: 1
        $x_1_2 = "main.GetFilesAndDirs" ascii //weight: 1
        $x_1_3 = "main.writeReadMe" ascii //weight: 1
        $x_1_4 = "main.fuckoff" ascii //weight: 1
        $x_1_5 = "main.file_not_encrypt" ascii //weight: 1
        $x_1_6 = "main.black_list_ext" ascii //weight: 1
        $x_1_7 = "main.white_list_ext" ascii //weight: 1
        $x_1_8 = "main.read_me_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

