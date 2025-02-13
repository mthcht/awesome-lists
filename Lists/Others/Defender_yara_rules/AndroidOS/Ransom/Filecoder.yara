rule Ransom_AndroidOS_Filecoder_2147744352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Filecoder!MTB"
        threat_id = "2147744352"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ssspbahk.so" ascii //weight: 1
        $x_1_2 = "QQqun 571012706 " ascii //weight: 1
        $x_1_3 = "Time has come!" ascii //weight: 1
        $x_1_4 = "Decrypt complete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_Filecoder_B_2147782845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Filecoder.B"
        threat_id = "2147782845"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Filecoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "how can they put your photo in this app, I think I need to tell you" ascii //weight: 2
        $x_2_2 = "http://wevx.xyz/post.php?uid=" ascii //weight: 2
        $x_2_3 = "Bitcoin address copy completed" ascii //weight: 2
        $x_2_4 = "UserID copy completed" ascii //weight: 2
        $x_2_5 = "luckyseven" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

