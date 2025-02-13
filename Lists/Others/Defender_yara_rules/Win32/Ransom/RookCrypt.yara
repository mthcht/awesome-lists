rule Ransom_Win32_RookCrypt_PA_2147805512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RookCrypt.PA!MTB"
        threat_id = "2147805512"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RookCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "Your files are encrypted" ascii //weight: 1
        $x_1_3 = "\\HowToRestoreYourFiles.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

