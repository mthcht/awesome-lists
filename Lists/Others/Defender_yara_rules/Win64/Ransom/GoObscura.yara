rule Ransom_Win64_GoObscura_YBH_2147951550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoObscura.YBH!MTB"
        threat_id = "2147951550"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoObscura"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README-OBSCURA.txt" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /all /quietmath" ascii //weight: 1
        $x_1_3 = "run/media/veracrypt1/Locker Deps/" ascii //weight: 1
        $x_1_4 = "DAEMON" ascii //weight: 1
        $x_1_5 = "[!!!] user not admin" ascii //weight: 1
        $x_1_6 = "encryption start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

