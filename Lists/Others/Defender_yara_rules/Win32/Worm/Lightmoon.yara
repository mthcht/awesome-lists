rule Worm_Win32_Lightmoon_A_2147573344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lightmoon.gen@mm!A"
        threat_id = "2147573344"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lightmoon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "mm: mass mailer worm"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "CopyYourUfd" ascii //weight: 20
        $x_20_2 = "CopyWoRm" ascii //weight: 20
        $x_20_3 = "setMyRegister" ascii //weight: 20
        $x_20_4 = "ScanEmail" ascii //weight: 20
        $x_20_5 = "fileHOst" ascii //weight: 20
        $x_20_6 = "Tolong Aku.." wide //weight: 20
        $x_1_7 = "----_=_NextPart_000_" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" wide //weight: 1
        $x_1_9 = "Software\\Microsoft\\Internet Account Manager\\Accounts\\" wide //weight: 1
        $x_1_10 = "\\Explorer\\Advanced\\Folder\\SuperHidden" wide //weight: 1
        $x_1_11 = "*.htm" wide //weight: 1
        $x_1_12 = ".cmd" wide //weight: 1
        $x_1_13 = "\\Explorer\\Advanced" wide //weight: 1
        $x_1_14 = "\\Explorer\\CabinetState" wide //weight: 1
        $x_1_15 = "\\Policies\\System" wide //weight: 1
        $x_1_16 = "\\startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 1 of ($x_1_*))) or
            ((4 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Lightmoon_B_2147582082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lightmoon.gen@mm!B"
        threat_id = "2147582082"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lightmoon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "mm: mass mailer worm"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "NewMoonlight" ascii //weight: 20
        $x_20_2 = "*\\AD:\\DataHellSpawn\\WARING_VIRII_LABORATORY\\Virus Ku\\Moonlight Update Baru\\Project1.vbp" ascii //weight: 20
        $x_5_3 = "TmrTungguconect" ascii //weight: 5
        $x_5_4 = "TmrKeyLog" ascii //weight: 5
        $x_5_5 = "TmrDos" ascii //weight: 5
        $x_1_6 = "ScanEmail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Lightmoon_H_2147619539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lightmoon.H"
        threat_id = "2147619539"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lightmoon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NewMoonlight" ascii //weight: 1
        $x_1_2 = "keylog" ascii //weight: 1
        $x_1_3 = "ScanEmail" ascii //weight: 1
        $x_1_4 = "DataHellSpawn\\WARING_VIRII_LABORATORY\\Virus Ku\\Moonlight" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

