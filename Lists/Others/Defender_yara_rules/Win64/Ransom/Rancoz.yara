rule Ransom_Win64_Rancoz_MA_2147847539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rancoz.MA!MTB"
        threat_id = "2147847539"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rancoz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Read HOW_TO_RECOVERY_FILES" ascii //weight: 1
        $x_1_2 = "Hello! Your company has been hacked!" ascii //weight: 1
        $x_1_3 = "Your data are stolen and encrypted" ascii //weight: 1
        $x_1_4 = "We are not a politically motivated group and we do not need anything other than your money. " ascii //weight: 1
        $x_1_5 = "Life is too short to be sad. Be not sad, money, it is only paper." ascii //weight: 1
        $x_1_6 = "Warning! If you do not pay the ransom we will attack your company repeatedly again" ascii //weight: 1
        $x_1_7 = "HOW_TO_RECOVERY_FILES.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

