rule HackTool_MacOS_Crack_AMTB_2147967475_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Crack!AMTB"
        threat_id = "2147967475"
        type = "HackTool"
        platform = "MacOS: "
        family = "Crack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cracked by blatant" ascii //weight: 1
        $x_1_2 = "keep reversing" ascii //weight: 1
        $x_1_3 = "t.me/blatants" ascii //weight: 1
        $x_1_4 = "bb_runAES128CryptorWithOperation:data:iv:key:" ascii //weight: 1
        $x_1_5 = "bb_AESDecryptedStringForIV:key:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

