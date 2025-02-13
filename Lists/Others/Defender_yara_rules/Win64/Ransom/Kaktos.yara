rule Ransom_Win64_Kaktos_A_2147845986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Kaktos.A!dha"
        threat_id = "2147845986"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Kaktos"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cAcTuS.readme.txt" wide //weight: 1
        $x_1_2 = "AES-NI GCM" ascii //weight: 1
        $x_1_3 = "CRYPTOGAMS" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_5 = "WMIC shadowcopy delete" wide //weight: 1
        $x_1_6 = "bcdedit /set {default} recoveryenabled no" wide //weight: 1
        $x_1_7 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 1
        $x_1_8 = "encrypted by Cactus" wide //weight: 1
        $x_1_9 = "email: cactus@mexicomail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

