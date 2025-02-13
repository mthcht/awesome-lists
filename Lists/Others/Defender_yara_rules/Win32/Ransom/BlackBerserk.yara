rule Ransom_Win32_BlackBerserk_MA_2147851845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackBerserk.MA!MTB"
        threat_id = "2147851845"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackBerserk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Black.Berserk@onionmail.org" ascii //weight: 1
        $x_1_2 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 1
        $x_1_3 = "Black_Recover.txt" wide //weight: 1
        $x_1_4 = ".Black" wide //weight: 1
        $x_1_5 = "All files have been stolen and encrypted by us and now have Black suffix" ascii //weight: 1
        $x_1_6 = "Global\\BlackMutex" wide //weight: 1
        $x_1_7 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_8 = "wbadmin delete catalog -quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

